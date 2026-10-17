import 'dart:async';

import 'package:http2/src/frames/frames.dart';
import 'package:http2/transport.dart';
import 'package:test/test.dart';

import 'client_test.dart' show ClientStreams;

void main() {
  for (final endStream in [false, true]) {
    test(
        'late headers after cancellation preserve other streams '
        '(endStream=$endStream)', () async {
      final streams = ClientStreams();
      final reader = streams.serverConnectionFrameReader;
      final writer = streams.serverConnectionFrameWriter;
      final client = streams.clientConnection;
      final settingsDone = Completer<void>();
      final responseHeaders = [
        Header.ascii(':status', '200'),
        Header.ascii('x-shared-dynamic-header', 'retained-after-cancellation'),
      ];
      Future<Frame> nextFrame() async {
        expect(await reader.moveNext(), isTrue);
        return reader.current;
      }

      Future<void> server() async {
        expect(await nextFrame(), isA<SettingsFrame>());
        writer.writeSettingsFrame([]);
        final ack = await nextFrame() as SettingsFrame;
        expect(ack.hasAckFlag, isTrue);
        writer.writeSettingsAckFrame();
        settingsDone.complete();

        final a = await nextFrame() as HeadersFrame;
        final reset = await nextFrame() as RstStreamFrame;
        expect(reset.header.streamId, a.header.streamId);
        expect(reset.errorCode, ErrorCode.CANCEL);
        final b = await nextFrame() as HeadersFrame;

        // Simulate response headers already in flight when A was reset.
        // B reuses the HPACK entry introduced by A's discarded headers.
        writer.writeHeadersFrame(a.header.streamId, responseHeaders,
            endStream: true);
        writer.writeHeadersFrame(b.header.streamId, responseHeaders,
            endStream: true);
        var closing = await nextFrame();
        if (closing is RstStreamFrame) {
          expect(closing.header.streamId, b.header.streamId);
          closing = await nextFrame();
        }
        expect(
            closing,
            isA<GoawayFrame>()
                .having((f) => f.errorCode, 'errorCode', ErrorCode.NO_ERROR));
        expect(await reader.moveNext(), isFalse);
        await writer.close();
      }

      Future<void> requests() async {
        await settingsDone.future;
        final a = client.makeRequest([Header.ascii(':method', 'GET')],
            endStream: endStream);
        final aPushes = a.peerPushes.toList();
        final discarded = a.incomingMessages.toList();
        a.terminate();
        expect(await discarded, isEmpty);
        final b = client
            .makeRequest([Header.ascii(':method', 'GET')], endStream: true);
        final bPushes = b.peerPushes.toList();
        await b.outgoingMessages.close();
        final received = await b.incomingMessages.toList();
        expect(received, hasLength(1));
        final headers = (received.single as HeadersStreamMessage).headers;
        expect(headers.map((h) => String.fromCharCodes(h.value)),
            ['200', 'retained-after-cancellation']);
        expect(client.isOpen, isTrue);
        expect(await aPushes, isEmpty);
        expect(await bPushes, isEmpty);
        await Future<void>.delayed(Duration.zero);
        await client.terminate();
      }

      try {
        await Future.wait([server(), requests()], eagerError: true);
      } finally {
        await reader.cancel();
        await client.terminate();
        unawaited(writer.close());
      }
    }, timeout: const Timeout(Duration(seconds: 5)));
  }
  test('headers on an unopened stream remain a protocol error', () async {
    final streams = ClientStreams();
    final reader = streams.serverConnectionFrameReader;
    final writer = streams.serverConnectionFrameWriter;
    final client = streams.clientConnection;
    Future<Frame> nextFrame() async {
      expect(await reader.moveNext(), isTrue);
      return reader.current;
    }

    try {
      expect(await nextFrame(), isA<SettingsFrame>());
      writer.writeSettingsFrame([]);
      expect(await nextFrame(), isA<SettingsFrame>());
      writer.writeSettingsAckFrame();
      writer.writeHeadersFrame(1, [Header.ascii(':status', '200')],
          endStream: true);
      expect(
          await nextFrame(),
          isA<GoawayFrame>().having(
              (f) => f.errorCode, 'errorCode', ErrorCode.PROTOCOL_ERROR));
      expect(client.isOpen, isFalse);
      expect(await reader.moveNext(), isFalse);
      await writer.close();
    } finally {
      await reader.cancel();
      await client.terminate();
      unawaited(writer.close());
    }
  }, timeout: const Timeout(Duration(seconds: 5)));
}
