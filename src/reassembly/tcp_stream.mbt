// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: reassembly/tcp_stream.mbt

///|
pub(all) struct TcpSegment {
  seq : UInt
  len : UInt
  data : Bytes
  timestamp : Double
} derive(Eq, Debug)

///|
pub(all) enum TcpStreamState {
  Listen
  SynSent
  SynReceived
  Established
  FinWait
  CloseWait
  Closed
} derive(Eq, Debug)

///|
pub struct TcpStreamReassembler {
  key : SessionKey
  mut state : TcpStreamState
  mut next_expected_seq : UInt
  buffer : Array[TcpSegment]
  reassembled_data : Array[Byte]
  mut out_of_order_count : Int
  mut gap_count : Int
  mut packet_count : Int
  mut is_seq_initialized : Bool
}

///|
pub fn TcpStreamReassembler::new(key : SessionKey) -> TcpStreamReassembler {
  {
    key,
    state: TcpStreamState::Listen,
    next_expected_seq: 0U,
    buffer: Array::new(),
    reassembled_data: Array::new(),
    out_of_order_count: 0,
    gap_count: 0,
    packet_count: 0,
    is_seq_initialized: false,
  }
}

///|
pub fn TcpStreamReassembler::get_key(self : TcpStreamReassembler) -> SessionKey {
  self.key
}

///|
pub fn TcpStreamReassembler::get_state(
  self : TcpStreamReassembler,
) -> TcpStreamState {
  self.state
}

///|
pub fn TcpStreamReassembler::set_initial_seq(
  self : TcpStreamReassembler,
  seq : UInt,
) -> Unit {
  self.next_expected_seq = seq
  self.is_seq_initialized = true
  self.state = TcpStreamState::Established
}

///|
pub fn TcpStreamReassembler::add_segment(
  self : TcpStreamReassembler,
  seq : UInt,
  data : Bytes,
  ts : Double,
  flags_syn? : Bool = false,
  flags_fin? : Bool = false,
  flags_rst? : Bool = false,
) -> Unit {
  self.packet_count = self.packet_count + 1

  if flags_rst {
    self.state = TcpStreamState::Closed
    return
  }

  if flags_syn {
    self.state = TcpStreamState::SynReceived
    self.next_expected_seq = seq + 1U
    self.is_seq_initialized = true
    return
  }

  if !self.is_seq_initialized {
    self.next_expected_seq = seq
    self.is_seq_initialized = true
    self.state = TcpStreamState::Established
  }

  let seg_len = data.length().reinterpret_as_uint()
  if seg_len == 0U && !flags_fin {
    return
  }

  if seq == self.next_expected_seq {
    // In-order segment
    for i = 0; i < data.length(); i = i + 1 {
      self.reassembled_data.push(data[i])
    }
    self.next_expected_seq = seq + seg_len + (if flags_fin { 1U } else { 0U })
    self.drain_buffer()
  } else if seq > self.next_expected_seq {
    // Out-of-order segment (future gap)
    self.out_of_order_count = self.out_of_order_count + 1
    self.gap_count = self.gap_count + 1
    self.buffer.push({ seq, len: seg_len, data, timestamp: ts })
    self.sort_buffer()
  } else {
    // Overlapping or duplicate segment
    let seq_end = seq + seg_len
    if seq_end > self.next_expected_seq {
      let overlap = (self.next_expected_seq - seq).reinterpret_as_int()
      let new_len = data.length() - overlap
      if new_len > 0 {
        for i = 0; i < new_len; i = i + 1 {
          self.reassembled_data.push(data[overlap + i])
        }
        self.next_expected_seq = seq_end
        self.drain_buffer()
      }
    }
  }

  if flags_fin {
    self.state = TcpStreamState::FinWait
  }
}

///|
pub fn TcpStreamReassembler::sort_buffer(self : TcpStreamReassembler) -> Unit {
  let len = self.buffer.length()
  for i = 0; i < len; i = i + 1 {
    for j = i + 1; j < len; j = j + 1 {
      if self.buffer[i].seq > self.buffer[j].seq {
        let tmp = self.buffer[i]
        self.buffer[i] = self.buffer[j]
        self.buffer[j] = tmp
      }
    }
  }
}

///|
pub fn TcpStreamReassembler::drain_buffer(self : TcpStreamReassembler) -> Unit {
  let mut changed = true
  while changed && self.buffer.length() > 0 {
    changed = false
    let mut match_idx = -1
    for i = 0; i < self.buffer.length(); i = i + 1 {
      let seg = self.buffer[i]
      if seg.seq == self.next_expected_seq {
        match_idx = i
        break
      }
    }
    if match_idx >= 0 {
      let seg = self.buffer.remove(match_idx)
      for k = 0; k < seg.data.length(); k = k + 1 {
        self.reassembled_data.push(seg.data[k])
      }
      self.next_expected_seq = seg.seq + seg.len
      changed = true
    }
  }
}

///|
pub fn TcpStreamReassembler::get_data(self : TcpStreamReassembler) -> Bytes {
  Bytes::from_array(self.reassembled_data)
}

///|
pub fn TcpStreamReassembler::get_stats(
  self : TcpStreamReassembler,
) -> (Int, Int, Int, Int) {
  (
    self.packet_count,
    self.out_of_order_count,
    self.gap_count,
    self.buffer.length(),
  )
}
