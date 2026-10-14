///|
pub struct Dnskey {
  priv flags : Int32
  priv algorithm : Int32
  priv data : Bytes
} derive(Eq, Debug)

///|
pub extend Dnskey with Eq::{equal, not_equal}

///|
pub extend Dnskey with @debug.Debug::{to_repr}

///|
pub fn Dnskey::parse(data : Bytes) -> Result[Dnskey, DnsError] {
  if data.length() < 5 || data.length() > 8192 {
    return Err(Malformed("DNSKEY requires header and bounded public key"))
  }
  if data[2] != 3 {
    return Err(Malformed("DNSKEY protocol must be three"))
  }
  let flags = u16_at(data, 0)
  if (flags & 0x0100) == 0 {
    return Err(Bogus("DNSKEY is not a zone key"))
  }
  if (flags & 0x0080) != 0 {
    return Err(Bogus("revoked DNSKEY is not accepted"))
  }
  Ok({ flags, algorithm: data[3].to_int(), data, })
}

///|
pub fn Dnskey::rdata(self : Dnskey) -> Bytes {
  self.data
}

///|
pub fn Dnskey::algorithm(self : Dnskey) -> Int32 {
  self.algorithm
}

///|
pub fn Dnskey::is_sep(self : Dnskey) -> Bool {
  (self.flags & 1) != 0
}

///|
pub struct Ds {
  priv key_tag : Int32
  priv algorithm : Int32
  priv digest_type : Int32
  priv digest : Bytes
} derive(Eq, Debug)

///|
pub extend Ds with Eq::{equal, not_equal}

///|
pub extend Ds with @debug.Debug::{to_repr}

///|
pub fn Ds::parse(data : Bytes) -> Result[Ds, DnsError] {
  if data.length() < 5 {
    return Err(Malformed("short DS record"))
  }
  let kind = data[3].to_int()
  let expected = match kind {
    1 => 20
    2 => 32
    4 => 48
    _ => 0
  }
  if expected != 0 && data.length() != expected + 4 {
    return Err(Malformed("DS digest length mismatch"))
  }
  if data.length() > 260 {
    return Err(ResourceLimit("DS digest too large"))
  }
  Ok({
    key_tag: u16_at(data, 0),
    algorithm: data[2].to_int(),
    digest_type: kind,
    digest: data[4:].to_owned(),
  })
}

///|
pub fn Ds::digest_type(self : Ds) -> Int32 {
  self.digest_type
}

///|
fn u16_at(data : Bytes, p : Int32) -> Int32 {
  (data[p].to_int() << 8) | data[p + 1].to_int()
}

///|
fn append16(out : Array[Byte], n : Int32) -> Unit {
  out.push((n >> 8).to_byte())
  out.push(n.to_byte())
}

///|
fn append_bytes(out : Array[Byte], data : Bytes) -> Unit {
  for b in data {
    out.push(b)
  }
}

///|
pub fn Ds::rdata(self : Ds) -> Bytes {
  let out : Array[Byte] = []
  append16(out, self.key_tag)
  out.push(self.algorithm.to_byte())
  out.push(self.digest_type.to_byte())
  append_bytes(out, self.digest)
  Bytes::from_array(out)
}

///|
/// Explicitly supported signing algorithms; legacy RSA/SHA1 is not enabled.
pub fn supported_algorithm(algorithm : Int32) -> Bool {
  algorithm == 8 ||
  algorithm == 10 ||
  algorithm == 13 ||
  algorithm == 14 ||
  algorithm == 15
}
