///|
/// Verify DNSSEC wire key/signature shapes using MoonCrypt, not mock digests.
pub fn verify_signature(
  key : Dnskey,
  message : Bytes,
  signature : Bytes,
) -> Result[Bool, DnsError] {
  let public = key.data[4:]
  if key.algorithm == 15 {
    if public.length() != 32 || signature.length() != 64 {
      return Err(Malformed("Ed25519 DNSKEY/RRSIG size"))
    }
    try {
      let k = @ed25519.PublicKey::new(public)
      Ok(k.verify(message[:], signature[:]))
    } catch {
      _ => Err(Malformed("invalid Ed25519 public key"))
    }
  } else if key.algorithm == 13 || key.algorithm == 14 {
    let n = if key.algorithm == 13 { 32 } else { 48 }
    if public.length() != n * 2 || signature.length() != n * 2 {
      return Err(Malformed("ECDSA DNSKEY/RRSIG size"))
    }
    try {
      let curve = if n == 32 { @ecdsa.P256 } else { @ecdsa.P384 }
      let k = @ecdsa.PublicKey::of_xy(public[:n], public[n:], curve~)
      Ok(k.verify(message[:], signature[:]))
    } catch {
      _ => Err(Malformed("invalid ECDSA public point"))
    }
  } else if key.algorithm == 8 || key.algorithm == 10 {
    if public.length() < 3 {
      return Err(Malformed("short RSA DNSKEY"))
    }
    let first = public[0].to_int()
    let offset = if first == 0 { 3 } else { 1 }
    let n = if first == 0 { u16_at(public.to_owned(), 1) } else { first }
    if n < 1 || n > 8 || offset + n >= public.length() {
      return Err(Unsupported("RSA exponent size or layout"))
    }
    if public[offset] == 0 {
      return Err(Malformed("non-minimal RSA exponent"))
    }
    let modulus = public[offset + n:]
    if modulus.length() < 128 || modulus.length() > 512 {
      return Err(Unsupported("RSA modulus must be 1024..4096 bits"))
    }
    if modulus[0] < 128 || (modulus[modulus.length() - 1].to_int() & 1) == 0 {
      return Err(Malformed("RSA modulus is not full-length odd integer"))
    }
    if signature.length() != modulus.length() {
      return Err(Malformed("RSA signature size"))
    }
    try {
      let digest = if key.algorithm == 8 { @rsa.Sha256 } else { @rsa.Sha512 }
      let k = @rsa.PublicKey::new(
        modulus,
        public[offset:offset + n],
        digest~,
        scheme=@rsa.Pkcs1,
      )
      Ok(k.verify(message[:], signature[:]))
    } catch {
      _ => Err(Malformed("invalid RSA key"))
    }
  } else {
    Err(Unsupported("DNSSEC signature algorithm not enabled"))
  }
}
