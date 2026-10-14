///|
/// Failure is distinct from a cryptographically authenticated absence.
pub(all) enum DnsError {
  Malformed(String)
  ResourceLimit(String)
  Unsupported(String)
  Bogus(String)
  Indeterminate(String)
  Stale(String)
} derive(Eq, Debug)

///|
pub(all) enum Verdict {
  Secure
  Insecure
  Bogus
  Indeterminate
} derive(Eq, Debug)

///|
pub fn DnsError::verdict(self : DnsError) -> Verdict {
  match self {
    Unsupported(_) | ResourceLimit(_) | Indeterminate(_) => Indeterminate
    Malformed(_) | Bogus(_) | Stale(_) => Bogus
  }
}

///|
/// Limits are checked before allocation, quadratic sorting or signature work.
pub(all) struct Limits {
  max_records : Int32
  max_signed_bytes : Int32
  max_signatures : Int32
  max_proofs : Int32
  max_chain : Int32
  max_nsec3_iterations : Int32
} derive(Eq, Debug)

///|
pub fn Limits::default() -> Limits {
  {
    max_records: 256,
    max_signed_bytes: 1048576,
    max_signatures: 32,
    max_proofs: 64,
    max_chain: 16,
    max_nsec3_iterations: 100,
  }
}

///|
pub fn Limits::validate(self : Limits) -> Result[Unit, DnsError] {
  if self.max_records < 1 || self.max_records > 4096 {
    return Err(ResourceLimit("records limit must be 1..4096"))
  }
  if self.max_signed_bytes < 255 || self.max_signed_bytes > 16777216 {
    return Err(ResourceLimit("signed byte limit must be 255..16777216"))
  }
  if self.max_signatures < 1 || self.max_signatures > 128 {
    return Err(ResourceLimit("signature limit must be 1..128"))
  }
  if self.max_proofs < 1 || self.max_proofs > 256 {
    return Err(ResourceLimit("proof limit must be 1..256"))
  }
  if self.max_chain < 1 || self.max_chain > 64 {
    return Err(ResourceLimit("chain limit must be 1..64"))
  }
  if self.max_nsec3_iterations < 0 || self.max_nsec3_iterations > 500 {
    return Err(ResourceLimit("NSEC3 iteration limit must be 0..500"))
  }
  Ok(())
}

///|
pub(all) struct TimePolicy {
  now : UInt32
  skew : UInt32
} derive(Eq, Debug)

///|
pub fn TimePolicy::at(now : UInt32) -> TimePolicy {
  { now, skew: 0U, }
}

///|
pub fn TimePolicy::validate(self : TimePolicy) -> Result[Unit, DnsError] {
  if self.skew > 3600U {
    Err(ResourceLimit("clock skew exceeds one hour"))
  } else {
    Ok(())
  }
}

///|
pub extend DnsError with Eq::{equal, not_equal}

///|
pub extend DnsError with @debug.Debug::{to_repr}

///|
pub extend Verdict with Eq::{equal, not_equal}

///|
pub extend Verdict with @debug.Debug::{to_repr}

///|
pub extend Limits with Eq::{equal, not_equal}

///|
pub extend Limits with @debug.Debug::{to_repr}

///|
pub extend TimePolicy with Eq::{equal, not_equal}

///|
pub extend TimePolicy with @debug.Debug::{to_repr}
