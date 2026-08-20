// Bounded out-of-order byte window used by stream reassembly integrations.

///|
pub(all) struct WindowSegment {
  sequence : UInt
  payload : Bytes
} derive(Eq, Debug)

///|
pub struct SegmentWindow {
  mut next : UInt
  max_buffer : Int
  mut buffered : Int
  mut dropped : Int
  segments : Array[WindowSegment]
}

///|
/// Create a bounded segment window.
pub fn SegmentWindow::new(
  initial_sequence? : UInt = 0U,
  max_buffer? : Int = 65536,
) -> SegmentWindow {
  let limit = if max_buffer < 1 { 1 } else { max_buffer }
  {
    next: initial_sequence,
    max_buffer: limit,
    buffered: 0,
    dropped: 0,
    segments: [],
  }
}

///|
/// Add a segment if it fits inside the configured memory window.
pub fn SegmentWindow::push(
  self : SegmentWindow,
  sequence : UInt,
  payload : Bytes,
) -> Bool {
  let len = payload.length()
  if len == 0 ||
    len > self.max_buffer ||
    sequence < self.next ||
    sequence - self.next > self.max_buffer.reinterpret_as_uint() {
    self.dropped = self.dropped + 1
    return false
  }
  for segment in self.segments {
    if segment.sequence == sequence {
      self.dropped = self.dropped + 1
      return false
    }
  }
  if self.buffered + len > self.max_buffer {
    self.dropped = self.dropped + 1
    return false
  }
  self.segments.push({ sequence, payload })
  self.buffered = self.buffered + len
  true
}

///|
fn append_bytes(target : Array[Byte], bytes : Bytes) -> Unit {
  for byte in bytes {
    target.push(byte)
  }
}

///|
/// Drain all segments that are contiguous from the current sequence.
pub fn SegmentWindow::drain_contiguous(self : SegmentWindow) -> Bytes {
  let output : Array[Byte] = []
  while true {
    let mut match_index = -1
    for i = 0; i < self.segments.length(); i = i + 1 {
      if self.segments[i].sequence == self.next {
        match_index = i
        break
      }
    }
    if match_index < 0 {
      break
    }
    let segment = self.segments.remove(match_index)
    append_bytes(output, segment.payload)
    self.next = self.next + segment.payload.length().reinterpret_as_uint()
    self.buffered = self.buffered - segment.payload.length()
  }
  Bytes::from_array(output)
}

///|
/// Return the sequence number expected by the next contiguous segment.
pub fn SegmentWindow::next_sequence(self : SegmentWindow) -> UInt {
  self.next
}

///|
/// Return bytes retained in the window.
pub fn SegmentWindow::buffered_bytes(self : SegmentWindow) -> Int {
  self.buffered
}

///|
/// Return the number of rejected segments.
pub fn SegmentWindow::dropped_segments(self : SegmentWindow) -> Int {
  self.dropped
}

///|
/// Return the number of segments currently waiting for a gap to close.
pub fn SegmentWindow::pending_segments(self : SegmentWindow) -> Int {
  self.segments.length()
}

///|
/// Return the lowest sequence currently waiting in the buffer.
pub fn SegmentWindow::oldest_pending_sequence(self : SegmentWindow) -> UInt? {
  if self.segments.length() == 0 {
    None
  } else {
    let mut value = self.segments[0].sequence
    for segment in self.segments {
      if segment.sequence < value {
        value = segment.sequence
      }
    }
    Some(value)
  }
}

///|
/// Return the distance from the expected sequence to the oldest pending segment.
pub fn SegmentWindow::gap_size(self : SegmentWindow) -> UInt {
  match self.oldest_pending_sequence() {
    None => 0U
    Some(sequence) =>
      if sequence > self.next {
        sequence - self.next
      } else {
        0U
      }
  }
}

///|
/// Return the configured maximum retained payload size.
pub fn SegmentWindow::capacity(self : SegmentWindow) -> Int {
  self.max_buffer
}

///|
/// Return whether a segment could fit without changing the window.
pub fn SegmentWindow::can_accept(
  self : SegmentWindow,
  sequence : UInt,
  length : Int,
) -> Bool {
  length > 0 &&
  length <= self.max_buffer &&
  sequence >= self.next &&
  sequence - self.next <= self.max_buffer.reinterpret_as_uint() &&
  self.buffered + length <= self.max_buffer &&
  !self.contains_sequence(sequence)
}

///|
/// Discard segments that end before a new stream base.
pub fn SegmentWindow::discard_before(
  self : SegmentWindow,
  sequence : UInt,
) -> Int {
  let mut removed = 0
  let mut i = self.segments.length() - 1
  while i >= 0 {
    let segment = self.segments[i]
    if segment.sequence + segment.payload.length().reinterpret_as_uint() <=
      sequence {
      self.buffered = self.buffered - segment.payload.length()
      let _ = self.segments.remove(i)
      removed = removed + 1
    }
    i = i - 1
  }
  removed
}

///|
/// Return whether a sequence number is already buffered.
pub fn SegmentWindow::contains_sequence(
  self : SegmentWindow,
  sequence : UInt,
) -> Bool {
  for segment in self.segments {
    if segment.sequence == sequence {
      return true
    }
  }
  false
}

///|
/// Return the largest contiguous payload currently available without consuming it.
pub fn SegmentWindow::contiguous_length(self : SegmentWindow) -> Int {
  let mut cursor = self.next
  let mut total = 0
  while true {
    let mut found = false
    for segment in self.segments {
      if segment.sequence == cursor {
        cursor = cursor + segment.payload.length().reinterpret_as_uint()
        total = total + segment.payload.length()
        found = true
        break
      }
    }
    if !found {
      break
    }
  }
  total
}

///|
/// Drop all buffered segments and reset the expected sequence.
pub fn SegmentWindow::reset(self : SegmentWindow, sequence : UInt) -> Unit {
  self.segments.clear()
  self.next = sequence
  self.buffered = 0
}
