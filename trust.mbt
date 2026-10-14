///|
/// DNSKEY set authenticated from an out-of-band key or signed parent DS.
pub struct TrustedKeys {
  priv zone : Name
  priv keys : Array[Dnskey]
  priv verified_at : UInt32
  priv lifetime : UInt32
  priv depth : Int32
} derive(Debug)

///|
pub extend TrustedKeys with @debug.Debug::{to_repr}

///|
pub fn TrustedKeys::zone(self : TrustedKeys) -> Name {
  self.zone
}

///|
pub fn TrustedKeys::depth(self : TrustedKeys) -> Int32 {
  self.depth
}

///|
pub fn TrustedKeys::remaining(
  self : TrustedKeys,
  now : UInt32,
) -> Result[UInt32, DnsError] {
  let elapsed = now - self.verified_at
  if elapsed >= self.lifetime {
    Err(Stale("trusted key set expired or clock moved backwards"))
  } else {
    Ok(self.lifetime - elapsed)
  }
}

///|
fn keys_from_set(
  records : Array[Record],
  zone : Name,
  limits : Limits,
) -> Result[Array[Dnskey], DnsError] {
  if records.is_empty() || records.length() > limits.max_records {
    return Err(ResourceLimit("DNSKEY set size"))
  }
  let keys : Array[Dnskey] = []
  for rr in records {
    if rr.rrtype != 48 || rr.owner != zone {
      return Err(Malformed("expected zone DNSKEY RRset"))
    }
    match Dnskey::parse(rr.data) {
      Ok(k) => if supported_algorithm(k.algorithm) { keys.push(k) }
      Err(Bogus(_)) => () // Non-zone/revoked keys cannot authenticate, but may exist in the signed set.
      Err(e) => return Err(e)
    }
  }
  if keys.is_empty() {
    return Err(Indeterminate("no enabled zone signing key"))
  }
  Ok(keys)
}

///|
/// Authenticate the complete DNSKEY RRset, not merely an anchor's presence.
pub fn anchor_keys(
  zone : Name,
  anchor : Dnskey,
  records : Array[Record],
  signatures : Array[Rrsig],
  time : TimePolicy,
  limits : Limits,
) -> Result[TrustedKeys, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let keys = match keys_from_set(records, zone, limits) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  if !keys.contains(anchor) {
    return Err(Bogus("anchor key absent from DNSKEY set"))
  }
  let set = match
    authenticate_with_key(records, signatures, zone, anchor, time, limits) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  Ok({ zone, keys, verified_at: time.now, lifetime: set.lifetime, depth: 0, })
}

///|
pub fn authenticate_rrset(
  records : Array[Record],
  signatures : Array[Rrsig],
  trusted : TrustedKeys,
  time : TimePolicy,
  limits : Limits,
) -> Result[AuthenticatedSet, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let trust_ttl = match trusted.remaining(time.now) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  if signatures.is_empty() {
    return Err(Indeterminate("no signatures"))
  }
  // Bound the complete search, including key-tag hashing and failed candidates.
  if signatures.length() > limits.max_signatures ||
    trusted.keys.length() > limits.max_signatures / signatures.length() {
    return Err(ResourceLimit("signature/key candidate budget"))
  }
  let mut failure : DnsError = Indeterminate("no usable signing key")
  for key in trusted.keys {
    match
      authenticate_with_key(
        records,
        signatures,
        trusted.zone,
        key,
        time,
        limits,
      ) {
      Ok(set) =>
        return Ok({
          ..set,
          lifetime: if set.lifetime < trust_ttl {
            set.lifetime
          } else {
            trust_ttl
          },
        })
      Err(e) => failure = e
    }
  }
  Err(failure)
}
