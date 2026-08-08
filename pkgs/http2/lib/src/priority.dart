// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// Priority information carried in the first HEADERS frame of a stream.
class StreamPriority {
  /// The stream this stream depends on. Zero represents the connection root.
  final int streamDependency;

  /// The encoded weight, in the inclusive range 0 through 255.
  ///
  /// The effective scheduling weight defined by HTTP/2 is this value plus one.
  final int weight;

  /// Whether this stream becomes the sole child of [streamDependency].
  final bool exclusive;

  const StreamPriority({
    this.streamDependency = 0,
    this.weight = 255,
    this.exclusive = false,
  })  : assert(streamDependency >= 0 && streamDependency <= 0x7fffffff),
        assert(weight >= 0 && weight <= 255);
}
