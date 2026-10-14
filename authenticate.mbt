///|
/// Cryptographically authenticated under an explicitly trusted supplied key.
/// Private fields prevent constructing an authenticated proof without verification.
pub struct AuthenticatedSet {
  priv records : Array[Record]
  priv zone : Name
  priv verified_at : UInt
  priv lifetime : UInt
  priv wildcard : Bool
} derive(Debug)

///|
pub extend AuthenticatedSet with @debug.Debug::{to_repr}

///|
pub fn AuthenticatedSet::records(self : AuthenticatedSet) -> Array[Record] {
  self.records.copy()
}

///|
pub fn AuthenticatedSet::owner(self : AuthenticatedSet) -> Name {
  self.records[0].owner
}

///|
pub fn AuthenticatedSet::rrtype(self : AuthenticatedSet) -> Int {
  self.records[0].rrtype
}

///|
pub fn AuthenticatedSet::zone(self : AuthenticatedSet) -> Name {
  self.zone
}

///|
pub fn AuthenticatedSet::lifetime(self : AuthenticatedSet) -> UInt {
  self.lifetime
}

///|
/// A supplied key is a trust assertion by the caller; DNS presence is not trust.
pub fn authenticate_with_key(
  records : Array[Record],
  signatures : Array[Rrsig],
  zone : Name,
  key : Dnskey,
  time : TimePolicy,
  limits : Limits,
) -> Result[AuthenticatedSet, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  match time.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if signatures.is_empty() {
    return Err(Indeterminate("no signatures"))
  }
  if signatures.length() > limits.max_signatures {
    return Err(ResourceLimit("signature count"))
  }
  let tag = match key.key_tag(zone) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let mut failure : DnsError = Indeterminate("no signature matches trusted key")
  for sig in signatures {
    if sig.signer != zone ||
      sig.key_tag != tag ||
      sig.algorithm != key.algorithm {
      continue
    }
    let remaining = match sig.remaining(time) {
      Ok(n) => n
      Err(e) => {
        failure = e
        continue
      }
    }
    let input = match signing_input(records, sig, limits) {
      Ok(b) => b
      Err(e) => {
        failure = e
        continue
      }
    }
    match verify_signature(key, input, sig.signature) {
      Err(e) => failure = e
      Ok(false) => failure = Bogus("RRSIG cryptographic verification failed")
      Ok(true) => {
        let mut lifetime = remaining
        if sig.original_ttl < lifetime {
          lifetime = sig.original_ttl
        }
        for rr in records {
          if rr.ttl < lifetime {
            lifetime = rr.ttl
          }
        }
        return Ok({
          records: records.copy(),
          zone,
          verified_at: time.now,
          lifetime,
          wildcard: sig.labels < records[0].owner.label_count(),
        })
      }
    }
  }
  Err(failure)
}
