///|
/// Advance exactly one authenticated delegation. No network lookup or implicit trust.
pub fn delegate_keys(
  parent : TrustedKeys,
  child : Name,
  ds_records : Array[Record],
  ds_signatures : Array[Rrsig],
  key_records : Array[Record],
  key_signatures : Array[Rrsig],
  time : TimePolicy,
  limits : Limits,
) -> Result[TrustedKeys, DnsError] {
  match limits.validate() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if parent.depth >= limits.max_chain {
    return Err(ResourceLimit("delegation chain depth"))
  }
  if child == parent.zone || !child.is_subdomain(parent.zone) {
    return Err(Bogus("child must be below the authenticated parent zone"))
  }
  if ds_records.is_empty() {
    return Err(Indeterminate("no DS: require authenticated denial instead"))
  }
  for rr in ds_records {
    if rr.owner != child || rr.rrtype != 43 {
      return Err(Malformed("expected child DS RRset"))
    }
  }
  let ds_set = match
    authenticate_rrset(ds_records, ds_signatures, parent, time, limits) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  if ds_set.wildcard {
    return Err(Bogus("DS delegation cannot be wildcard-expanded"))
  }
  let keys = match keys_from_set(key_records, child, limits) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  if keys.length() > limits.max_records / ds_records.length() {
    return Err(ResourceLimit("DS/key association budget"))
  }
  if key_signatures.is_empty() ||
    key_signatures.length() > limits.max_signatures ||
    keys.length() > limits.max_signatures / key_signatures.length() {
    return Err(ResourceLimit("child signature/key budget"))
  }
  let ds : Array[Ds] = []
  for rr in ds_records {
    match Ds::parse(rr.data) {
      Ok(d) => ds.push(d)
      Err(e) => return Err(e)
    }
  }
  let mut supported_ds = false
  let mut matched = false
  let mut failure : DnsError = Bogus("no DNSKEY matches supported parent DS")
  for key in keys {
    let mut accepted = false
    for d in ds {
      if d.digest_type == 2 && supported_algorithm(d.algorithm) {
        supported_ds = true
        match d.matches(child, key) {
          Ok(true) => {
            accepted = true
            matched = true
          }
          Ok(false) => ()
          Err(e) => return Err(e)
        }
      }
    }
    if !accepted {
      continue
    }
    match
      authenticate_with_key(
        key_records, key_signatures, child, key, time, limits,
      ) {
      Err(e) => failure = e
      Ok(set) =>
        return Ok({
          zone: child,
          keys,
          verified_at: time.now,
          lifetime: if set.lifetime < ds_set.lifetime {
            set.lifetime
          } else {
            ds_set.lifetime
          },
          depth: parent.depth + 1,
        })
    }
  }
  if !supported_ds {
    return Err(Unsupported("no enabled DS digest/algorithm pair"))
  }
  if !matched {
    return Err(Bogus("parent DS does not bind supplied DNSKEY"))
  }
  Err(failure)
}
