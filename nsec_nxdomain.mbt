///|
/// Complete bounded NSEC closest-encloser and wildcard denial.
/// Requires an explicit exact-owner closest-encloser proof (no inferred empty nonterminals).
pub fn nsec_nxdomain(
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
    return Err(ResourceLimit("NSEC ancestor depth"))
  }
  if proofs.is_empty() || proofs.length() > limits.max_proofs {
    return Err(ResourceLimit("NSEC proof count"))
  }
  let decoded : Array[(Nsec, UInt)] = []
  for proof in proofs {
    let rr = match ensure_proof(proof, zone, 47, now) {
      Ok(r) => r
      Err(e) => return Err(e)
    }
    let n = match Nsec::parse(rr) {
      Ok(n) => n
      Err(e) => return Err(e)
    }
    if !n.next.is_subdomain(zone) {
      return Err(Bogus("NSEC successor outside signer zone"))
    }
    if n.owner == name {
      return Err(Bogus("NXDOMAIN query owner exists"))
    }
    if name.is_subdomain(n.owner) &&
      (
        n.bitmap.contains(39) ||
        n.bitmap.contains(5) ||
        (n.bitmap.contains(2) && !n.bitmap.contains(6))
      ) {
      return Err(Indeterminate("query is beneath alias or delegation boundary"))
    }
    let ttl = match proof.remaining(now) {
      Ok(n) => n
      Err(e) => return Err(e)
    }
    decoded.push((n, ttl))
  }
  let mut closest : Name? = None
  let mut closest_ttl = 0U
  let mut candidate = name.parent()
  while candidate is Some(c) {
    if !c.is_subdomain(zone) {
      break
    }
    for entry in decoded {
      if entry.0.owner == c {
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
    None => return Err(Indeterminate("missing closest-encloser NSEC"))
  }
  let next = match next_closer(name, ce) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let wildcard = match ce.wildcard() {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let mut next_ttl : UInt? = None
  let mut wildcard_ttl : UInt? = None
  for entry in decoded {
    if entry.0.owner == wildcard {
      return Err(Bogus("closest-encloser wildcard exists"))
    }
    if entry.0.covers(next) {
      next_ttl = Some(entry.1)
    }
    if entry.0.covers(wildcard) {
      wildcard_ttl = Some(entry.1)
    }
  }
  match (next_ttl, wildcard_ttl) {
    (Some(a), Some(b)) =>
      Ok({ kind: NxDomain, lifetime: min_ttl(closest_ttl, min_ttl(a, b)), })
    _ =>
      Err(Indeterminate("need both next-closer and wildcard interval coverage"))
  }
}

///|
fn next_closer(name : Name, closest : Name) -> Result[Name, DnsError] {
  if name == closest || !name.is_subdomain(closest) {
    return Err(Bogus("invalid closest encloser"))
  }
  let mut next = name
  while next.parent() is Some(p) {
    if p == closest {
      return Ok(next)
    }
    next = p
  }
  Err(Bogus("closest encloser not an ancestor"))
}

///|
fn min_ttl(a : UInt, b : UInt) -> UInt {
  if a < b {
    a
  } else {
    b
  }
}
