///|
test "policy validates limits and does not label unsupported crypto bogus" {
  assert_eq(Limits::default().validate(), Ok(()))
  assert_eq(TimePolicy::at(1U).validate(), Ok(()))
  assert_eq(DnsError::Unsupported("algorithm").verdict(), Indeterminate)
  let invalid = { ..Limits::default(), max_chain: 0, }
  assert_true(invalid.validate() is Err(_))
  assert_true(TimePolicy::{ now: 1U, skew: 3601U, }.validate() is Err(_))
}
