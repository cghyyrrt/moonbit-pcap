// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: reassembly/ip_fragment.mbt

///|
pub(all) struct IpFragment {
  identification : UInt
  fragment_offset : UInt // Offset in 8-byte units
  more_fragments : Bool
  data : Bytes
} derive(Eq, Debug)

///|
pub struct IpFragmentReassembler {
  identification : UInt
  fragments : Array[IpFragment]
  mut is_complete : Bool
}

///|
pub fn IpFragmentReassembler::new(id : UInt) -> IpFragmentReassembler {
  { identification: id, fragments: Array::new(), is_complete: false }
}

///|
pub fn IpFragmentReassembler::add_fragment(
  self : IpFragmentReassembler,
  frag : IpFragment,
) -> Unit {
  self.fragments.push(frag)
  if !frag.more_fragments {
    self.is_complete = true
  }
}

///|
pub fn IpFragmentReassembler::reassemble(
  self : IpFragmentReassembler,
) -> Bytes? {
  if !self.is_complete || self.fragments.length() == 0 {
    return None
  }
  // Sort fragments by offset
  let len = self.fragments.length()
  for i = 0; i < len; i = i + 1 {
    for j = i + 1; j < len; j = j + 1 {
      if self.fragments[i].fragment_offset > self.fragments[j].fragment_offset {
        let tmp = self.fragments[i]
        self.fragments[i] = self.fragments[j]
        self.fragments[j] = tmp
      }
    }
  }

  let buf = Array::new()
  for frag in self.fragments {
    for k = 0; k < frag.data.length(); k = k + 1 {
      buf.push(frag.data[k])
    }
  }
  Some(Bytes::from_array(buf))
}
