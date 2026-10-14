///|
test "ecosystem association supplies key tags and rejects unknown digests" {
  let owner = Name::parse("example.").unwrap()
  let key = Dnskey::parse(b"\x01\x01\x03\x0f\x01").unwrap()
  let f = key_fingerprint(owner, key).unwrap()
  assert_eq(key.key_tag(owner), Ok(f.key_tag))
  assert_eq(f.sha256_digest.length(), 64)
  let unknown = Ds::parse(b"\x00\x01\x0f\xff\x00").unwrap()
  assert_true(unknown.matches(owner, key) is Err(Unsupported(_)))
  assert_true(Name::parse("*.example.").unwrap().host_text() is Err(_))
}
