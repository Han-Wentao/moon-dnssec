///|
pub(all) enum DenialKind {
  NoData
  NxDomain
  InsecureDelegation
} derive(Eq, Debug)

///|
pub extend DenialKind with Eq::{equal, not_equal}

///|
pub extend DenialKind with @debug.Debug::{to_repr}

///|
pub struct Denial {
  kind : DenialKind
  lifetime : UInt
} derive(Debug)

///|
pub extend Denial with @debug.Debug::{to_repr}

///|
pub fn Denial::kind(self : Denial) -> DenialKind {
  self.kind
}

///|
pub fn Denial::lifetime(self : Denial) -> UInt {
  self.lifetime
}

///|
pub fn Denial::verdict(self : Denial) -> Verdict {
  if self.kind == InsecureDelegation {
    Insecure
  } else {
    Secure
  }
}

///|
pub struct Nsec {
  owner : Name
  next : Name
  bitmap : TypeBitmap
} derive(Debug)

///|
pub extend Nsec with @debug.Debug::{to_repr}

///|
/// Parsing alone does not authenticate this record.
pub fn Nsec::parse(record : Record) -> Result[Nsec, DnsError] {
  if record.rrtype != 47 {
    return Err(Malformed("expected NSEC"))
  }
  let (next, p) = match read_name(record.data, 0) {
    Ok(x) => x
    Err(e) => return Err(e)
  }
  let bitmap = match TypeBitmap::parse(record.data[p:].to_owned()) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  if !bitmap.contains(47) || !bitmap.contains(46) {
    return Err(Malformed("NSEC bitmap must include NSEC and RRSIG"))
  }
  Ok({ owner: record.owner, next, bitmap, })
}

///|
pub fn Nsec::covers(self : Nsec, name : Name) -> Bool {
  let a = self.owner.canonical_compare(name)
  let b = name.canonical_compare(self.next)
  let order = self.owner.canonical_compare(self.next)
  if order < 0 {
    a < 0 && b < 0
  } else {
    a < 0 || b < 0
  }
}

///|
fn valid_query(
  zone : Name,
  name : Name,
  rrtype : Int,
) -> Result[Unit, DnsError] {
  if !name.is_subdomain(zone) {
    return Err(Bogus("query outside proof zone"))
  }
  if rrtype < 1 ||
    rrtype > 65535 ||
    rrtype == 41 ||
    (rrtype >= 249 && rrtype <= 255) {
    return Err(Unsupported("meta query type cannot use this denial API"))
  }
  Ok(())
}

///|
fn absence_kind(
  bitmap : TypeBitmap,
  rrtype : Int,
  at_apex : Bool,
) -> Result[DenialKind, DnsError] {
  if bitmap.contains(rrtype) || bitmap.contains(5) {
    return Err(Bogus("requested type or CNAME exists"))
  }
  let delegation = bitmap.contains(2) && !bitmap.contains(6)
  if rrtype == 43 {
    if at_apex {
      return Err(Indeterminate("DS absence must come from parent zone"))
    }
    if delegation {
      return Ok(InsecureDelegation)
    }
  }
  if delegation {
    return Err(
      Indeterminate("parent proof is not authoritative below delegation"),
    )
  }
  Ok(NoData)
}

///|
pub fn nsec_nodata(
  proof : AuthenticatedSet,
  zone : Name,
  name : Name,
  rrtype : Int,
  now : UInt,
) -> Result[Denial, DnsError] {
  match valid_query(zone, name, rrtype) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let record = match ensure_proof(proof, zone, 47, now) {
    Ok(r) => r
    Err(e) => return Err(e)
  }
  let nsec = match Nsec::parse(record) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  if nsec.owner != name {
    return Err(Indeterminate("exact-name NSEC needed for NODATA"))
  }
  if !nsec.next.is_subdomain(zone) {
    return Err(Bogus("NSEC successor outside zone"))
  }
  let kind = match absence_kind(nsec.bitmap, rrtype, name == zone) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let lifetime = match proof.remaining(now) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  Ok({ kind, lifetime, })
}
