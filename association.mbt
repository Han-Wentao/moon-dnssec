///|
/// ASCII host presentation required by the reused MoonZoneGuard association API.
pub fn Name::host_text(self : Name) -> Result[String, DnsError] {
  let out = StringBuilder()
  if self.labels.is_empty() {
    return Ok(".")
  }
  for label in self.labels {
    for b in label {
      let n = b.to_int()
      if !((n >= 97 && n <= 122) || (n >= 48 && n <= 57) || n == 45 || n == 95) {
        return Err(Unsupported("DS association requires ASCII host labels"))
      }
      out.write_char(n.unsafe_to_char())
    }
    out.write_string(".")
  }
  Ok(out.to_string())
}

///|
fn key_fingerprint(
  owner : Name,
  key : Dnskey,
) -> Result[@zone.DnskeyFingerprint, DnsError] {
  let name = match owner.host_text() {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let rr : @zone.ResourceRecord = {
    owner: name,
    origin: ".",
    ttl: 0,
    class_name: "IN",
    record_type: "DNSKEY",
    rdata: [
      key.flags.to_string(),
      "3",
      key.algorithm.to_string(),
      @base64.encode(key.data[4:]),
    ],
    line: 0,
    column: 0,
  }
  match @zone.dnskey_ds_sha256(rr) {
    Ok(f) => Ok(f)
    Err(e) => Err(Unsupported("association dependency: " + e))
  }
}

///|
pub fn Dnskey::key_tag(self : Dnskey, owner : Name) -> Result[Int, DnsError] {
  match key_fingerprint(owner, self) {
    Ok(f) => Ok(f.key_tag)
    Err(e) => Err(e)
  }
}

///|
/// SHA256 DS is delegated to the established ecosystem implementation.
/// Other digest types are reported unsupported, never silently downgraded.
pub fn Ds::matches(
  self : Ds,
  owner : Name,
  key : Dnskey,
) -> Result[Bool, DnsError] {
  if self.digest_type != 2 {
    return Err(Unsupported("only DS SHA256 is enabled"))
  }
  if self.algorithm != key.algorithm {
    return Ok(false)
  }
  match key_fingerprint(owner, key) {
    Err(e) => Err(e)
    Ok(f) => {
      if f.key_tag != self.key_tag {
        return Ok(false)
      }
      Ok(hex(self.digest) == f.sha256_digest.to_lower())
    }
  }
}

///|
fn hex(data : Bytes) -> String {
  let out = StringBuilder()
  let alphabet = "0123456789abcdef"
  for b in data {
    out.write_char(alphabet[b.to_int() >> 4].to_int().unsafe_to_char())
    out.write_char(alphabet[b.to_int() & 15].to_int().unsafe_to_char())
  }
  out.to_string()
}
