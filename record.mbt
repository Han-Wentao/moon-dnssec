///|
/// A caller-supplied resource record, never a compressed DNS message fragment.
pub struct Record {
  priv owner : Name
  priv rrtype : Int
  priv ttl : UInt
  priv data : Bytes
} derive(Eq, Debug)

///|
pub extend Record with Eq::{equal, not_equal}

///|
pub extend Record with @debug.Debug::{to_repr}

///|
pub fn Record::new(
  owner : Name,
  rrtype : Int,
  ttl : UInt,
  data : Bytes,
) -> Result[Record, DnsError] {
  if rrtype < 1 || rrtype > 65535 || rrtype == 41 || rrtype == 255 {
    return Err(Malformed("invalid RRset type"))
  }
  if data.length() > 65535 {
    return Err(ResourceLimit("RDATA exceeds wire field"))
  }
  if ttl >= 0x80000000U {
    return Err(Malformed("TTL exceeds RFC2181 limit"))
  }
  Ok({ owner, rrtype, ttl, data, })
}

///|
pub fn Record::owner(self : Record) -> Name {
  self.owner
}

///|
pub fn Record::rrtype(self : Record) -> Int {
  self.rrtype
}

///|
pub fn Record::rdata(self : Record) -> Bytes {
  self.data
}

///|
pub fn Record::ttl(self : Record) -> UInt {
  self.ttl
}

///|
/// Canonical RDATA for enabled types; known unimplemented name-bearing types fail closed.
pub fn Record::canonical_rdata(self : Record) -> Result[Bytes, DnsError] {
  let data = self.data
  let t = self.rrtype
  if t == 1 {
    return if data.length() == 4 {
      Ok(data)
    } else {
      Err(Malformed("A length"))
    }
  }
  if t == 28 {
    return if data.length() == 16 {
      Ok(data)
    } else {
      Err(Malformed("AAAA length"))
    }
  }
  if t == 2 || t == 5 || t == 12 || t == 39 {
    return match Name::from_wire(data) {
      Ok(n) => Ok(n.wire())
      Err(e) => Err(e)
    }
  }
  if t == 15 || t == 33 {
    let prefix = if t == 15 { 2 } else { 6 }
    let name = match read_name(data, prefix) {
      Ok(x) => x
      Err(e) => return Err(e)
    }
    if name.1 != data.length() {
      return Err(Malformed("trailing name-bearing RDATA"))
    }
    let out : Array[Byte] = []
    append_bytes(out, data[:prefix].to_owned())
    append_bytes(out, name.0.wire())
    return Ok(Bytes::from_array(out))
  }
  if t == 6 {
    let (mname, p) = match read_name(data, 0) {
      Ok(x) => x
      Err(e) => return Err(e)
    }
    let (rname, q) = match read_name(data, p) {
      Ok(x) => x
      Err(e) => return Err(e)
    }
    if data.length() - q != 20 {
      return Err(Malformed("SOA numeric fields"))
    }
    let out : Array[Byte] = []
    append_bytes(out, mname.wire())
    append_bytes(out, rname.wire())
    append_bytes(out, data[q:].to_owned())
    return Ok(Bytes::from_array(out))
  }
  if t == 47 {
    let (next, p) = match read_name(data, 0) {
      Ok(x) => x
      Err(e) => return Err(e)
    }
    if p == data.length() {
      return Err(Malformed("NSEC requires type bitmap"))
    }
    let out : Array[Byte] = []
    append_bytes(out, next.wire())
    append_bytes(out, data[p:].to_owned())
    return Ok(Bytes::from_array(out))
  }
  if t == 16 || t == 99 {
    let mut p = 0
    if data.is_empty() {
      return Err(Malformed("empty TXT RDATA"))
    }
    while p < data.length() {
      let n = data[p].to_int()
      p += n + 1
      if p > data.length() {
        return Err(Malformed("truncated TXT string"))
      }
    }
    return Ok(data)
  }
  if t == 3 ||
    t == 4 ||
    t == 7 ||
    t == 8 ||
    t == 9 ||
    t == 14 ||
    t == 17 ||
    t == 18 ||
    t == 21 ||
    t == 24 ||
    t == 26 ||
    t == 30 ||
    t == 35 ||
    t == 36 ||
    t == 38 ||
    t == 45 ||
    t == 55 ||
    t == 58 ||
    t == 64 ||
    t == 65 ||
    t == 107 ||
    t == 250 ||
    t == 251 ||
    t == 252 {
    return Err(
      Unsupported("canonicalization for this known RR type is disabled"),
    )
  }
  // RFC3597 unknown types are opaque and cannot carry DNS compression pointers.
  Ok(data)
}
