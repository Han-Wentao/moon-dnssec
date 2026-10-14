///|
/// TTL cache freshness uses serial elapsed time, rejecting backwards clock changes.
pub fn AuthenticatedSet::remaining(
  self : AuthenticatedSet,
  now : UInt32,
) -> Result[UInt32, DnsError] {
  let elapsed = now - self.verified_at
  if elapsed >= self.lifetime {
    Err(Stale("authenticated RRset expired or clock moved backwards"))
  } else {
    Ok(self.lifetime - elapsed)
  }
}

///|
/// Return a copy suitable for a resolver cache, with the residual trust TTL.
/// This does not create a new trust assertion or extend signature lifetime.
pub fn AuthenticatedSet::cache_records(
  self : AuthenticatedSet,
  now : UInt32,
) -> Result[Array[Record], DnsError] {
  let ttl = match self.remaining(now) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let records : Array[Record] = []
  for rr in self.records {
    records.push({ ..rr, ttl, })
  }
  Ok(records)
}

///|
pub fn AuthenticatedSet::is_wildcard_expansion(self : AuthenticatedSet) -> Bool {
  self.wildcard
}

///|
fn ensure_proof(
  set : AuthenticatedSet,
  zone : Name,
  rrtype : Int32,
  now : UInt32,
) -> Result[Record, DnsError] {
  match set.remaining(now) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if set.zone != zone ||
    set.rrtype() != rrtype ||
    !set.owner().is_subdomain(zone) {
    return Err(Bogus("denial proof zone/type mismatch"))
  }
  if set.wildcard {
    return Err(Bogus("denial proof cannot be wildcard-expanded"))
  }
  if set.records.length() != 1 {
    return Err(Malformed("denial proof must have one record"))
  }
  Ok(set.records[0])
}

///|
/// Expose proof preconditions to downstream tools without exposing trust constructors.
pub fn AuthenticatedSet::denial_record(
  self : AuthenticatedSet,
  zone : Name,
  rrtype : Int32,
  now : UInt32,
) -> Result[Record, DnsError] {
  if rrtype != 47 && rrtype != 50 {
    return Err(Malformed("expected NSEC or NSEC3 type"))
  }
  ensure_proof(self, zone, rrtype, now)
}
