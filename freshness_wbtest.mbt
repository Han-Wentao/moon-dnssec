///|
test "cache never reissues original TTL or extends trust lifetime" {
  let owner = Name::parse("example.").unwrap()
  let rr = Record::new(owner, 1, 100U, b"1234").unwrap()
  // Whitebox only: public consumers cannot construct AuthenticatedSet.
  let set : AuthenticatedSet = {
    records: [rr],
    zone: owner,
    verified_at: 10U,
    lifetime: 20U,
    wildcard: false,
  }
  assert_eq(set.cache_records(15U).unwrap()[0].ttl(), 15U)
  assert_true(set.cache_records(30U) is Err(Stale(_)))
  assert_true(set.remaining(9U) is Err(Stale(_)))
  assert_true(set.denial_record(owner, 47, 15U) is Err(Bogus(_)))
  let wrap = { ..set, verified_at: 0xfffffff0U, lifetime: 32U, }
  assert_eq(wrap.remaining(0U), Ok(16U))
}
