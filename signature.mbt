///|
pub struct Rrsig {
  priv covered : Int
  priv algorithm : Int
  priv labels : Int
  priv original_ttl : UInt
  priv expiration : UInt
  priv inception : UInt
  priv key_tag : Int
  priv signer : Name
  priv signature : Bytes
} derive(Eq, Debug)

///|
pub extend Rrsig with Eq::{equal, not_equal}

///|
pub extend Rrsig with @debug.Debug::{to_repr}

///|
pub fn Rrsig::parse(data : Bytes) -> Result[Rrsig, DnsError] {
  if data.length() < 20 || data.length() > 16384 {
    return Err(Malformed("RRSIG size outside supported bounds"))
  }
  let (signer, end) = match read_name(data, 18) {
    Ok(x) => x
    Err(e) => return Err(e)
  }
  if end == data.length() {
    return Err(Malformed("empty RRSIG signature"))
  }
  Ok({
    covered: u16_at(data, 0),
    algorithm: data[2].to_int(),
    labels: data[3].to_int(),
    original_ttl: u32_at(data, 4),
    expiration: u32_at(data, 8),
    inception: u32_at(data, 12),
    key_tag: u16_at(data, 16),
    signer,
    signature: data[end:].to_owned(),
  })
}

///|
pub fn Rrsig::signer(self : Rrsig) -> Name {
  self.signer
}

///|
pub fn Rrsig::covered_type(self : Rrsig) -> Int {
  self.covered
}

///|
/// RFC1982 arithmetic: validity intervals must be less than half the serial space.
pub fn Rrsig::remaining(
  self : Rrsig,
  time : TimePolicy,
) -> Result[UInt, DnsError] {
  match time.validate() {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let span = self.expiration - self.inception
  if span >= 0x80000000U {
    return Err(Bogus("ambiguous RRSIG validity interval"))
  }
  let elapsed = time.now - self.inception
  if elapsed <= span {
    return Ok(span - elapsed)
  }
  let until_start = self.inception - time.now
  if until_start <= time.skew {
    return Ok(span)
  }
  let since_end = time.now - self.expiration
  if since_end <= time.skew {
    return Ok(0U)
  }
  Err(Stale("RRSIG outside validity interval"))
}

///|
fn Rrsig::preamble(self : Rrsig) -> Bytes {
  let out : Array[Byte] = []
  append16(out, self.covered)
  out.push(self.algorithm.to_byte())
  out.push(self.labels.to_byte())
  append32(out, self.original_ttl)
  append32(out, self.expiration)
  append32(out, self.inception)
  append16(out, self.key_tag)
  append_bytes(out, self.signer.wire())
  Bytes::from_array(out)
}

///|
pub fn Rrsig::rdata(self : Rrsig) -> Bytes {
  let out : Array[Byte] = []
  append_bytes(out, self.preamble())
  append_bytes(out, self.signature)
  Bytes::from_array(out)
}

///|
fn u32_at(data : Bytes, p : Int) -> UInt {
  (data[p].to_uint() << 24) |
  (data[p + 1].to_uint() << 16) |
  (data[p + 2].to_uint() << 8) |
  data[p + 3].to_uint()
}

///|
fn append32(out : Array[Byte], n : UInt) -> Unit {
  out.push((n >> 24).to_byte())
  out.push((n >> 16).to_byte())
  out.push((n >> 8).to_byte())
  out.push(n.to_byte())
}
