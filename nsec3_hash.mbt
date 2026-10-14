///|
/// RFC5155 SHA1 iteration with policy checked before any hashing.
pub fn nsec3_hash(
  name : Name,
  salt : Bytes,
  iterations : Int32,
  limits : Limits,
) -> Result[Bytes, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if salt.length() > 255 {
    return Err(Malformed("NSEC3 salt length"))
  }
  if iterations < 0 || iterations > limits.max_nsec3_iterations {
    return Err(ResourceLimit("NSEC3 iterations exceed policy"))
  }
  let initial : Array[Byte] = []
  append_bytes(initial, name.wire())
  append_bytes(initial, salt)
  let mut hash = @sha1.hash(Bytes::from_array(initial)[:])
  for i = 0; i < iterations; i = i + 1 {
    let next : Array[Byte] = []
    append_bytes(next, hash)
    append_bytes(next, salt)
    hash = @sha1.hash(Bytes::from_array(next)[:])
  }
  Ok(hash)
}

///|
pub fn nsec3_label(hash : Bytes) -> Result[String, DnsError] {
  if hash.length() != 20 {
    return Err(Malformed("NSEC3 SHA1 hash length"))
  }
  let alphabet = "0123456789abcdefghijklmnopqrstuv"
  let out = StringBuilder()
  let mut acc = 0
  let mut bits = 0
  for b in hash {
    acc = (acc << 8) | b.to_int()
    bits += 8
    while bits >= 5 {
      bits -= 5
      let n = (acc >> bits) & 31
      out.write_char(alphabet[n].to_int().unsafe_to_char())
    }
    acc = acc & ((1 << bits) - 1)
  }
  Ok(out.to_string())
}

///|
pub fn decode_nsec3_label(label : Bytes) -> Result[Bytes, DnsError] {
  if label.length() != 32 {
    return Err(Malformed("NSEC3 owner hash label must have 32 characters"))
  }
  let out : Array[Byte] = []
  let mut acc = 0
  let mut bits = 0
  for b in label {
    let c = b.to_int()
    let n = if c >= 48 && c <= 57 {
      c - 48
    } else if c >= 97 && c <= 118 {
      c - 97 + 10
    } else {
      return Err(Malformed("NSEC3 owner is not base32hex"))
    }
    acc = (acc << 5) | n
    bits += 5
    if bits >= 8 {
      bits -= 8
      out.push(((acc >> bits) & 255).to_byte())
      acc = acc & ((1 << bits) - 1)
    }
  }
  Ok(Bytes::from_array(out))
}
