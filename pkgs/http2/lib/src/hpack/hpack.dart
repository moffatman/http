// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// Implements a [HPackContext] for encoding/decoding headers according to the
/// HPACK specificaiton. See here for more information:
///   https://tools.ietf.org/html/draft-ietf-httpbis-header-compression-10
library http2.hpack;

import 'dart:convert' show ascii;
import 'dart:typed_data';

import '../byte_utils.dart';
import 'huffman.dart';
import 'huffman_table.dart';

/// Exception raised due to encoding/decoding errors.
class HPackDecodingException implements Exception {
  final String _message;

  HPackDecodingException(this._message);

  @override
  String toString() => 'HPackDecodingException: $_message';
}

/// A HPACK encoding/decoding context.
///
/// This is a statefull class, so encoding/decoding changes internal state.
class HPackContext {
  final HPackEncoder encoder = HPackEncoder();
  final HPackDecoder decoder = HPackDecoder();

  HPackContext(
      {int maxSendingHeaderTableSize = 4096,
      int maxReceivingHeaderTableSize = 4096}) {
    encoder.updateMaxSendingHeaderTableSize(maxSendingHeaderTableSize);
    decoder.updateMaxReceivingHeaderTableSize(maxReceivingHeaderTableSize);
  }
}

/// A HTTP/2 header.
class Header {
  final List<int> name;
  final List<int> value;
  final bool neverIndexed;

  Header(this.name, this.value, {this.neverIndexed = false});

  factory Header.ascii(String name, String value, {bool neverIndexed = false}) {
    // Specs: `However, header field names MUST be converted to lowercase prior
    // to their encoding in HTTP/2. A request or response containing uppercase
    // header field names MUST be treated as malformed (Section 8.1.2.6).`
    return Header(ascii.encode(name.toLowerCase()), ascii.encode(value), neverIndexed: neverIndexed);
  }
}

/// A stateful HPACK decoder.
class HPackDecoder {
  late int _maxHeaderTableSize;

  final IndexTable _table = IndexTable();

  void updateMaxReceivingHeaderTableSize(int newMaximumSize) {
    _maxHeaderTableSize = newMaximumSize;
  }

  List<Header> decode(List<int> data) {
    var offset = 0;

    int readInteger(int prefixBits) {
      assert(prefixBits <= 8 && prefixBits > 0);

      var byte = data[offset++] & ((1 << prefixBits) - 1);

      int integer;
      if (byte == ((1 << prefixBits) - 1)) {
        // Length encodeded.
        integer = 0;
        var shift = 0;
        while (true) {
          var done = (data[offset] & 0x80) != 0x80;
          integer += (data[offset++] & 0x7f) << shift;
          shift += 7;
          if (done) break;
        }
        integer += (1 << prefixBits) - 1;
      } else {
        // In place length.
        integer = byte;
      }

      return integer;
    }

    List<int> readStringLiteral() {
      var isHuffmanEncoding = (data[offset] & 0x80) != 0;
      var length = readInteger(7);

      var sublist = viewOrSublist(data, offset, length);
      offset += length;
      if (isHuffmanEncoding) {
        return http2HuffmanCodec.decode(sublist);
      } else {
        return sublist;
      }
    }

    Header readHeaderFieldInternal(int index, {bool neverIndexed = false}) {
      List<int> name, value;
      if (index > 0) {
        name = _table.lookup(index).name;
        value = readStringLiteral();
      } else {
        name = readStringLiteral();
        value = readStringLiteral();
      }
      return Header(name, value, neverIndexed: neverIndexed);
    }

    try {
      var headers = <Header>[];
      while (offset < data.length) {
        var byte = data[offset];
        var isIndexedField = (byte & 0x80) != 0;
        var isIncrementalIndexing = (byte & 0xc0) == 0x40;

        var isWithoutIndexing = (byte & 0xf0) == 0;
        var isNeverIndexing = (byte & 0xf0) == 0x10;
        var isDynamicTableSizeUpdate = (byte & 0xe0) == 0x20;

        if (isIndexedField) {
          var index = readInteger(7);
          var field = _table.lookup(index);
          headers.add(field);
        } else if (isIncrementalIndexing) {
          var field = readHeaderFieldInternal(readInteger(6));
          _table.addHeaderField(field);
          headers.add(field);
        } else if (isWithoutIndexing) {
          headers.add(readHeaderFieldInternal(readInteger(4)));
        } else if (isNeverIndexing) {
          headers
              .add(readHeaderFieldInternal(readInteger(4), neverIndexed: true));
        } else if (isDynamicTableSizeUpdate) {
          var newMaxSize = readInteger(5);
          if (newMaxSize <= _maxHeaderTableSize) {
            _table.updateMaxSize(newMaxSize);
          } else {
            throw HPackDecodingException('Dynamic table size update failed: '
                'A new value of $newMaxSize exceeds the limit of '
                '$_maxHeaderTableSize');
          }
        } else {
          throw HPackDecodingException('Invalid encoding of headers.');
        }
      }
      return headers;
      // ignore: avoid_catching_errors
    } on RangeError catch (e) {
      throw HPackDecodingException('$e');
    } on HuffmanDecodingException catch (e) {
      throw HPackDecodingException('$e');
    }
  }
}

/// A stateful HPACK encoder.
class HPackEncoder {
  final IndexTable _table = IndexTable();

  int _advertisedMaximumTableSize = 4096;
  int _maximumTableSize = 4096;
  int? _smallestPendingMaximumTableSize;
  bool _tableSizeUpdatePending = false;

  void updateMaxSendingHeaderTableSize(int newMaximumSize) {
    if (newMaximumSize < 0) {
      throw ArgumentError.value(
          newMaximumSize, 'newMaximumSize', 'must not be negative');
    }
    if (newMaximumSize == _maximumTableSize) return;

    if (newMaximumSize < _advertisedMaximumTableSize) {
      final pendingMinimum = _smallestPendingMaximumTableSize;
      if (pendingMinimum == null || newMaximumSize < pendingMinimum) {
        _smallestPendingMaximumTableSize = newMaximumSize;
      }
    }
    _maximumTableSize = newMaximumSize;
    _table.updateMaxSize(newMaximumSize);
    _tableSizeUpdatePending = _smallestPendingMaximumTableSize != null ||
        newMaximumSize != _advertisedMaximumTableSize;
  }

  List<int> encode(List<Header> headers) {
    var bytesBuilder = BytesBuilder();

    void writeInteger(int prefixBits, int prefix, int value) {
      assert(prefixBits <= 8);
      assert(prefix & ((1 << prefixBits) - 1) == 0);
      var currentByte = prefix;

      if (value < (1 << prefixBits) - 1) {
        currentByte |= value;
        bytesBuilder.addByte(currentByte);
      } else {
        // Length encodeded.
        currentByte |= (1 << prefixBits) - 1;
        value -= (1 << prefixBits) - 1;
        bytesBuilder.addByte(currentByte);
        var done = false;
        while (!done) {
          currentByte = value & 0x7f;
          value = value >> 7;
          done = value == 0;
          if (!done) currentByte |= 0x80;
          bytesBuilder.addByte(currentByte);
        }
      }
    }

    void writeStringLiteral(List<int> bytes) {
      final huffmanBytes = http2HuffmanCodec.encode(bytes);
      if (huffmanBytes.length < bytes.length) {
        writeInteger(7, 0x80, huffmanBytes.length);
        bytesBuilder.add(huffmanBytes);
      } else {
        writeInteger(7, 0, bytes.length);
        bytesBuilder.add(bytes);
      }
    }

    void writeLiteralHeader(
        Header header, int prefixBits, int prefix, bool addToDynamicTable) {
      final nameIndex = _table.indexOfName(header.name);
      writeInteger(prefixBits, prefix, nameIndex ?? 0);
      if (nameIndex == null) writeStringLiteral(header.name);
      writeStringLiteral(header.value);
      if (addToDynamicTable) _table.addHeaderField(header);
    }

    if (_tableSizeUpdatePending) {
      final pendingMinimum = _smallestPendingMaximumTableSize;
      if (pendingMinimum != null && pendingMinimum != _maximumTableSize) {
        writeInteger(5, 0x20, pendingMinimum);
      }
      writeInteger(5, 0x20, _maximumTableSize);
      _advertisedMaximumTableSize = _maximumTableSize;
      _smallestPendingMaximumTableSize = null;
      _tableSizeUpdatePending = false;
    }

    for (var header in headers) {
      if (header.neverIndexed) {
        writeLiteralHeader(header, 4, 0x10, false);
        continue;
      }

      final exactIndex = _table.indexOf(header);
      if (exactIndex != null) {
        writeInteger(7, 0x80, exactIndex);
      } else if (_table.canAddHeaderField(header)) {
        writeLiteralHeader(header, 6, 0x40, true);
      } else {
        writeLiteralHeader(header, 4, 0, false);
      }
    }

    return bytesBuilder.takeBytes();
  }
}

class IndexTable {
  static final List<Header?> _staticTable = [
    null,
    Header(ascii.encode(':authority'), const []),
    Header(ascii.encode(':method'), ascii.encode('GET')),
    Header(ascii.encode(':method'), ascii.encode('POST')),
    Header(ascii.encode(':path'), ascii.encode('/')),
    Header(ascii.encode(':path'), ascii.encode('/index.html')),
    Header(ascii.encode(':scheme'), ascii.encode('http')),
    Header(ascii.encode(':scheme'), ascii.encode('https')),
    Header(ascii.encode(':status'), ascii.encode('200')),
    Header(ascii.encode(':status'), ascii.encode('204')),
    Header(ascii.encode(':status'), ascii.encode('206')),
    Header(ascii.encode(':status'), ascii.encode('304')),
    Header(ascii.encode(':status'), ascii.encode('400')),
    Header(ascii.encode(':status'), ascii.encode('404')),
    Header(ascii.encode(':status'), ascii.encode('500')),
    Header(ascii.encode('accept-charset'), const []),
    Header(ascii.encode('accept-encoding'), ascii.encode('gzip, deflate')),
    Header(ascii.encode('accept-language'), const []),
    Header(ascii.encode('accept-ranges'), const []),
    Header(ascii.encode('accept'), const []),
    Header(ascii.encode('access-control-allow-origin'), const []),
    Header(ascii.encode('age'), const []),
    Header(ascii.encode('allow'), const []),
    Header(ascii.encode('authorization'), const []),
    Header(ascii.encode('cache-control'), const []),
    Header(ascii.encode('content-disposition'), const []),
    Header(ascii.encode('content-encoding'), const []),
    Header(ascii.encode('content-language'), const []),
    Header(ascii.encode('content-length'), const []),
    Header(ascii.encode('content-location'), const []),
    Header(ascii.encode('content-range'), const []),
    Header(ascii.encode('content-type'), const []),
    Header(ascii.encode('cookie'), const []),
    Header(ascii.encode('date'), const []),
    Header(ascii.encode('etag'), const []),
    Header(ascii.encode('expect'), const []),
    Header(ascii.encode('expires'), const []),
    Header(ascii.encode('from'), const []),
    Header(ascii.encode('host'), const []),
    Header(ascii.encode('if-match'), const []),
    Header(ascii.encode('if-modified-since'), const []),
    Header(ascii.encode('if-none-match'), const []),
    Header(ascii.encode('if-range'), const []),
    Header(ascii.encode('if-unmodified-since'), const []),
    Header(ascii.encode('last-modified'), const []),
    Header(ascii.encode('link'), const []),
    Header(ascii.encode('location'), const []),
    Header(ascii.encode('max-forwards'), const []),
    Header(ascii.encode('proxy-authenticate'), const []),
    Header(ascii.encode('proxy-authorization'), const []),
    Header(ascii.encode('range'), const []),
    Header(ascii.encode('referer'), const []),
    Header(ascii.encode('refresh'), const []),
    Header(ascii.encode('retry-after'), const []),
    Header(ascii.encode('server'), const []),
    Header(ascii.encode('set-cookie'), const []),
    Header(ascii.encode('strict-transport-security'), const []),
    Header(ascii.encode('transfer-encoding'), const []),
    Header(ascii.encode('user-agent'), const []),
    Header(ascii.encode('vary'), const []),
    Header(ascii.encode('via'), const []),
    Header(ascii.encode('www-authenticate'), const []),
  ];

  final List<Header> _dynamicTable = [];

  /// The maximum size the dynamic table can grow to before entries need to be
  /// evicted.
  int _maximumSize = 4096;

  /// The current size of the dynamic table.
  int _currentSize = 0;

  IndexTable();

  int? indexOf(Header header) {
    for (var i = 1; i < _staticTable.length; i++) {
      final candidate = _staticTable[i]!;
      if (_bytesEqual(candidate.name, header.name) &&
          _bytesEqual(candidate.value, header.value)) {
        return i;
      }
    }
    for (var i = 0; i < _dynamicTable.length; i++) {
      final candidate = _dynamicTable[i];
      if (_bytesEqual(candidate.name, header.name) &&
          _bytesEqual(candidate.value, header.value)) {
        return _staticTable.length + i;
      }
    }
    return null;
  }

  int? indexOfName(List<int> name) {
    for (var i = 1; i < _staticTable.length; i++) {
      if (_bytesEqual(_staticTable[i]!.name, name)) return i;
    }
    for (var i = 0; i < _dynamicTable.length; i++) {
      if (_bytesEqual(_dynamicTable[i].name, name)) {
        return _staticTable.length + i;
      }
    }
    return null;
  }

  bool canAddHeaderField(Header header) =>
      _maximumSize != 0 && _sizeOf(header) <= _maximumSize;

  /// Updates the maximum size which the dynamic table can grow to.
  void updateMaxSize(int newMaxDynTableSize) {
    _maximumSize = newMaxDynTableSize;
    _reduce();
  }

  /// Lookup an item by index.
  Header lookup(int index) {
    if (index <= 0) {
      throw HPackDecodingException(
          'Invalid index (was: $index) for table lookup.');
    }
    if (index < _staticTable.length) {
      return _staticTable[index]!;
    }
    index -= _staticTable.length;
    if (index < _dynamicTable.length) {
      return _dynamicTable[index];
    }
    throw HPackDecodingException(
        'Invalid index (was: $index) for table lookup.');
  }

  /// Adds a new header field to the dynamic table - and evicts entries as
  /// necessary.
  void addHeaderField(Header header) {
    _dynamicTable.insert(0, header);
    _currentSize += _sizeOf(header);
    _reduce();
  }

  /// Removes as many entries as required to be within the limit of
  /// [_maximumSize].
  void _reduce() {
    while (_currentSize > _maximumSize) {
      var h = _dynamicTable.removeLast();
      _currentSize -= _sizeOf(h);
    }
  }

  /// Returns the "size" a [header] has.
  ///
  /// This is specified to be the number of octets of name/value plus 32.
  int _sizeOf(Header header) => header.name.length + header.value.length + 32;
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}
