///|
test "serial validity spans wrap but not half-space ambiguity" {
  let sig : Rrsig = {
    covered: 1,
    algorithm: 15,
    labels: 1,
    original_ttl: 60U,
    expiration: 20U,
    inception: 0xfffffff0U,
    key_tag: 1,
    signer: Name::parse("example.").unwrap(),
    signature: b"s",
  }
  assert_eq(sig.remaining(TimePolicy::at(10U)), Ok(10U))
  assert_true(sig.remaining(TimePolicy::at(21U)) is Err(Stale(_)))
  assert_eq(sig.remaining({ now: 21U, skew: 1U, }), Ok(0U))
  assert_eq(Rrsig::parse(sig.rdata()), Ok(sig))
  assert_true(
    { ..sig, expiration: 0x7ffffff0U, }.remaining(TimePolicy::at(0U)) is Err(_),
  )
  assert_true(Rrsig::parse(b"short") is Err(_))
}
