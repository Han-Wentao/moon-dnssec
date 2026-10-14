///|
/// Authenticate NSEC3 NXDOMAIN with one parameter set and complete proof closure.
/// Opt-out coverage is deliberately Indeterminate, never Secure NXDOMAIN.
pub fn nsec3_nxdomain(
  proofs : Array[AuthenticatedSet],
  zone : Name,
  name : Name,
  now : UInt,
  limits : Limits,
) -> Result[Denial, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  match valid_query(zone, name, 1) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if name == zone {
    return Err(Bogus("zone apex exists"))
  }
  if name.label_count() - zone.label_count() > limits.max_chain {
    return Err(ResourceLimit("NSEC3 ancestor hashing depth"))
  }
  if proofs.is_empty() || proofs.length() > limits.max_proofs {
    return Err(ResourceLimit("NSEC3 proof count"))
  }
  let decoded : Array[(Nsec3, UInt)] = []
  for proof in proofs {
    let rr = match ensure_proof(proof, zone, 50, now) {
      Ok(r) => r
      Err(e) => return Err(e)
    }
    let n = match Nsec3::parse(rr, zone, limits) {
      Ok(n) => n
      Err(e) => return Err(e)
    }
    if !decoded.is_empty() &&
      (n.salt != decoded[0].0.salt || n.iterations != decoded[0].0.iterations) {
      return Err(Bogus("mixed NSEC3 salts or iteration parameters"))
    }
    let ttl = match proof.remaining(now) {
      Ok(t) => t
      Err(e) => return Err(e)
    }
    decoded.push((n, ttl))
  }
  let params = decoded[0].0
  let query_hash = match
    nsec3_hash(name, params.salt, params.iterations, limits) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  for entry in decoded {
    if entry.0.owner_hash == query_hash {
      return Err(Bogus("NXDOMAIN query hash exists"))
    }
  }
  let mut closest : Name? = None
  let mut closest_ttl = 0U
  let mut candidate = name.parent()
  while candidate is Some(c) {
    if !c.is_subdomain(zone) {
      break
    }
    let hash = match nsec3_hash(c, params.salt, params.iterations, limits) {
      Ok(b) => b
      Err(e) => return Err(e)
    }
    for entry in decoded {
      if entry.0.owner_hash == hash {
        let bitmap = entry.0.bitmap
        if bitmap.contains(5) ||
          bitmap.contains(39) ||
          (bitmap.contains(2) && !bitmap.contains(6)) {
          return Err(Indeterminate("closest encloser is alias or delegation"))
        }
        closest = Some(c)
        closest_ttl = entry.1
        break
      }
    }
    if closest is Some(_) {
      break
    }
    candidate = c.parent()
  }
  let ce = match closest {
    Some(c) => c
    None => return Err(Indeterminate("missing matching closest-encloser hash"))
  }
  let next = match next_closer(name, ce) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let wildcard = match ce.wildcard() {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let next_hash = match
    nsec3_hash(next, params.salt, params.iterations, limits) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let wildcard_hash = match
    nsec3_hash(wildcard, params.salt, params.iterations, limits) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let mut next_ttl : UInt? = None
  let mut wildcard_ttl : UInt? = None
  let mut opt_out = false
  for entry in decoded {
    let n = entry.0
    if n.owner_hash == wildcard_hash {
      return Err(Bogus("wildcard hash exists"))
    }
    if n.covers_hash(next_hash) {
      if n.opt_out {
        opt_out = true
      } else {
        next_ttl = Some(entry.1)
      }
    }
    if n.covers_hash(wildcard_hash) {
      if n.opt_out {
        opt_out = true
      } else {
        wildcard_ttl = Some(entry.1)
      }
    }
  }
  match (next_ttl, wildcard_ttl) {
    (Some(a), Some(b)) =>
      Ok({ kind: NxDomain, lifetime: min_ttl(closest_ttl, min_ttl(a, b)), })
    _ =>
      if opt_out {
        Err(Indeterminate("opt-out cannot authenticate general NXDOMAIN"))
      } else {
        Err(Indeterminate("missing next-closer or wildcard NSEC3 coverage"))
      }
  }
}
