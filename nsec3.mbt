///|
pub struct Nsec3 {
  owner_hash : Bytes
  next_hash : Bytes
  salt : Bytes
  iterations : Int
  opt_out : Bool
  bitmap : TypeBitmap
} derive(Debug)

///|
pub extend Nsec3 with @debug.Debug::{to_repr}

///|
/// Decode bounded SHA1 NSEC3 and enforce its immediate signer-zone owner.
pub fn Nsec3::parse(
  record : Record,
  zone : Name,
  limits : Limits,
) -> Result[Nsec3, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if record.rrtype != 50 {
    return Err(Malformed("expected NSEC3"))
  }
  if !record.owner.is_subdomain(zone) ||
    record.owner.label_count() != zone.label_count() + 1 {
    return Err(Bogus("NSEC3 owner must be hash directly below signer zone"))
  }
  let owner_hash = match decode_nsec3_label(record.owner.labels[0]) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let d = record.data
  if d.length() < 6 {
    return Err(Malformed("short NSEC3 header"))
  }
  if d[0] != 1 {
    return Err(Unsupported("only NSEC3 SHA1 is enabled"))
  }
  if d[1].to_int() > 1 {
    return Err(Malformed("NSEC3 reserved flags"))
  }
  let iterations = u16_at(d, 2)
  if iterations > limits.max_nsec3_iterations {
    return Err(ResourceLimit("NSEC3 proof iterations"))
  }
  let salt_length = d[4].to_int()
  let p = 5 + salt_length
  if p >= d.length() || d[p] != 20 || d.length() - p - 1 < 20 {
    return Err(Malformed("NSEC3 salt or next hash length"))
  }
  let bitmap = match TypeBitmap::parse(d[p + 21:].to_owned()) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  Ok({
    owner_hash,
    next_hash: d[p + 1:p + 21].to_owned(),
    salt: d[5:p].to_owned(),
    iterations,
    opt_out: d[1] == 1,
    bitmap,
  })
}

///|
pub fn Nsec3::covers_hash(self : Nsec3, hash : Bytes) -> Bool {
  if hash.length() != 20 {
    return false
  }
  let a = bytes_compare(self.owner_hash, hash)
  let b = bytes_compare(hash, self.next_hash)
  if bytes_compare(self.owner_hash, self.next_hash) < 0 {
    a < 0 && b < 0
  } else {
    a < 0 || b < 0
  }
}

///|
pub fn nsec3_nodata(
  proof : AuthenticatedSet,
  zone : Name,
  name : Name,
  rrtype : Int,
  now : UInt,
  limits : Limits,
) -> Result[Denial, DnsError] {
  match valid_query(zone, name, rrtype) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let record = match ensure_proof(proof, zone, 50, now) {
    Ok(r) => r
    Err(e) => return Err(e)
  }
  let n = match Nsec3::parse(record, zone, limits) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let hash = match nsec3_hash(name, n.salt, n.iterations, limits) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  if n.owner_hash != hash {
    return Err(Indeterminate("exact-name NSEC3 needed for NODATA"))
  }
  let kind = match absence_kind(n.bitmap, rrtype, name == zone) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let lifetime = match proof.remaining(now) {
    Ok(t) => t
    Err(e) => return Err(e)
  }
  Ok({ kind, lifetime, })
}
