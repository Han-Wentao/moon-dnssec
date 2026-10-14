///|
test "canonical signing input sorts and deduplicates without altering TTL source" {
  let owner = Name::parse("example.").unwrap()
  let sig : Rrsig = {
    covered: 1,
    algorithm: 15,
    labels: 1,
    original_ttl: 60U,
    expiration: 200U,
    inception: 100U,
    key_tag: 1,
    signer: owner,
    signature: b"s",
  }
  let a = Record::new(owner, 1, 10U, b"\x01\x02\x03\x04").unwrap()
  let b = Record::new(owner, 1, 20U, b"\x02\x02\x03\x04").unwrap()
  let first = signing_input([b, a, a], sig, Limits::default()).unwrap()
  assert_eq(first, signing_input([a, b], sig, Limits::default()).unwrap())
  assert_eq(
    first.length(),
    sig.preamble().length() + 2 * (owner.wire().length() + 14),
  )
  assert_true(signing_input([], sig, Limits::default()) is Err(_))
  assert_true(
    signing_input([a, b], sig, { ..Limits::default(), max_records: 1, })
    is Err(ResourceLimit(_)),
  )
}
