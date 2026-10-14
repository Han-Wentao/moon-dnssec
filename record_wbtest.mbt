///|
test "RDATA canonicalizes embedded names and rejects malformed layouts" {
  let owner = Name::parse("example.").unwrap()
  let mx = Record::new(owner, 15, 60U, b"\x00\x0a\x02MX\x07EXAMPLE\x00").unwrap()
  assert_eq(mx.canonical_rdata().unwrap(), b"\x00\x0a\x02mx\x07example\x00")
  assert_true(
    Record::new(owner, 1, 1U, b"x").unwrap().canonical_rdata() is Err(_),
  )
  assert_true(
    Record::new(owner, 16, 1U, b"\x03ab").unwrap().canonical_rdata() is Err(_),
  )
  assert_true(
    Record::new(owner, 35, 1U, b"x").unwrap().canonical_rdata()
    is Err(Unsupported(_)),
  )
  assert_eq(
    Record::new(owner, 65280, 1U, b"opaque").unwrap().canonical_rdata(),
    Ok(b"opaque"),
  )
  assert_true(Record::new(owner, 1, 0x80000000U, b"1234") is Err(_))
}
