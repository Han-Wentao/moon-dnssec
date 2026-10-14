///|
/// Build RFC4034 signing input. IN class only; RRsets must be homogeneous.
pub fn signing_input(
  records : Array[Record],
  signature : Rrsig,
  limits : Limits,
) -> Result[Bytes, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if records.is_empty() {
    return Err(Malformed("empty RRset"))
  }
  if records.length() > limits.max_records {
    return Err(ResourceLimit("RRset record count"))
  }
  let owner = records[0].owner
  let rrtype = records[0].rrtype
  if signature.covered != rrtype {
    return Err(Bogus("RRSIG covers another type"))
  }
  if signature.original_ttl >= 0x80000000U {
    return Err(Malformed("RRSIG original TTL"))
  }
  if !owner.is_subdomain(signature.signer) {
    return Err(Bogus("signer does not contain owner"))
  }
  let signed_owner = match owner.signed_owner(signature.labels) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  if !signed_owner.is_subdomain(signature.signer) {
    return Err(Bogus("wildcard outside signer zone"))
  }
  let mut total = signature.preamble().length()
  for rr in records {
    if rr.owner != owner || rr.rrtype != rrtype {
      return Err(Malformed("mixed owners or types in RRset"))
    }
    total += signed_owner.wire().length() + 10 + rr.data.length()
    if total > limits.max_signed_bytes {
      return Err(ResourceLimit("RRset signing bytes"))
    }
  }
  let canonical : Array[Bytes] = []
  for rr in records {
    match rr.canonical_rdata() {
      Ok(b) => canonical.push(b)
      Err(e) => return Err(e)
    }
  }
  canonical.sort_by(bytes_compare)
  let out : Array[Byte] = []
  append_bytes(out, signature.preamble())
  let mut previous : Bytes? = None
  for data in canonical {
    if previous == Some(data) {
      continue
    }
    append_bytes(out, signed_owner.wire())
    append16(out, rrtype)
    append16(out, 1)
    append32(out, signature.original_ttl)
    append16(out, data.length())
    append_bytes(out, data)
    previous = Some(data)
  }
  Ok(Bytes::from_array(out))
}
