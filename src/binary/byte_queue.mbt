// Mutable byte queue for incremental capture and protocol stream ingestion.

///|
pub struct ByteQueue {
  data : Array[Byte]
  mut head : Int
}

///|
/// Create an empty byte queue.
pub fn ByteQueue::new() -> ByteQueue {
  { data: [], head: 0 }
}

///|
/// Return the number of unread bytes.
pub fn ByteQueue::length(self : ByteQueue) -> Int {
  self.data.length() - self.head
}

///|
/// Return whether no unread bytes remain.
pub fn ByteQueue::is_empty(self : ByteQueue) -> Bool {
  self.length() == 0
}

///|
/// Append one byte.
pub fn ByteQueue::push(self : ByteQueue, byte : Byte) -> Unit {
  self.data.push(byte)
}

///|
/// Append a byte sequence.
pub fn ByteQueue::push_bytes(self : ByteQueue, bytes : Bytes) -> Unit {
  for byte in bytes {
    self.data.push(byte)
  }
}

///|
/// Return the first unread byte without consuming it.
pub fn ByteQueue::peek(self : ByteQueue) -> Byte? {
  if self.is_empty() {
    None
  } else {
    Some(self.data[self.head])
  }
}

///|
/// Consume a bounded number of bytes, preserving the queue on failure.
pub fn ByteQueue::take(self : ByteQueue, count : Int) -> Bytes? {
  if count < 0 || count > self.length() {
    return None
  }
  let result : Array[Byte] = []
  for i = 0; i < count; i = i + 1 {
    result.push(self.data[self.head + i])
  }
  self.head = self.head + count
  self.compact_if_needed()
  Some(Bytes::from_array(result))
}

///|
/// Consume every unread byte.
pub fn ByteQueue::take_all(self : ByteQueue) -> Bytes {
  match self.take(self.length()) {
    Some(bytes) => bytes
    None => Bytes::from_array([])
  }
}

///|
/// Remove all queued bytes.
pub fn ByteQueue::clear(self : ByteQueue) -> Unit {
  self.data.clear()
  self.head = 0
}

///|
/// Copy unread bytes without consuming them.
pub fn ByteQueue::snapshot(self : ByteQueue) -> Bytes {
  let result : Array[Byte] = []
  for i = self.head; i < self.data.length(); i = i + 1 {
    result.push(self.data[i])
  }
  Bytes::from_array(result)
}

///|
/// Return true if the unread suffix starts with the supplied prefix.
pub fn ByteQueue::starts_with(self : ByteQueue, prefix : Bytes) -> Bool {
  if prefix.length() > self.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if self.data[self.head + i] != prefix[i] {
      return false
    }
  }
  true
}

///|
/// Drop a prefix only when it is present.
pub fn ByteQueue::consume_prefix(self : ByteQueue, prefix : Bytes) -> Bool {
  if !self.starts_with(prefix) {
    false
  } else {
    let _ = self.take(prefix.length())
    true
  }
}

///|
/// Find the first occurrence of a byte prefix in unread data.
pub fn ByteQueue::find(self : ByteQueue, needle : Bytes) -> Int? {
  if needle.length() == 0 {
    return Some(0)
  }
  if needle.length() > self.length() {
    return None
  }
  for offset = 0; offset <= self.length() - needle.length(); offset = offset + 1 {
    let mut matches = true
    for i = 0; i < needle.length(); i = i + 1 {
      if self.data[self.head + offset + i] != needle[i] {
        matches = false
        break
      }
    }
    if matches {
      return Some(offset)
    }
  }
  None
}

///|
/// Consume through and including the first matching delimiter.
pub fn ByteQueue::take_through(self : ByteQueue, delimiter : Bytes) -> Bytes? {
  match self.find(delimiter) {
    None => None
    Some(offset) => self.take(offset + delimiter.length())
  }
}

///|
/// Return the unread byte at a relative offset.
pub fn ByteQueue::get(self : ByteQueue, offset : Int) -> Byte? {
  if offset < 0 || offset >= self.length() {
    None
  } else {
    Some(self.data[self.head + offset])
  }
}

///|
/// Compact consumed storage to keep long-running streams bounded.
pub fn ByteQueue::compact_if_needed(self : ByteQueue) -> Unit {
  if self.head > 1024 && self.head * 2 > self.data.length() {
    let remaining : Array[Byte] = []
    for i = self.head; i < self.data.length(); i = i + 1 {
      remaining.push(self.data[i])
    }
    self.data.clear()
    for byte in remaining {
      self.data.push(byte)
    }
    self.head = 0
  }
}
