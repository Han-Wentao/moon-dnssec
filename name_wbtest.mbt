///|
test "absolute names canonicalize and use DNS order" {
  let a = Name::parse("Z.Example.").unwrap()
  let b = Name::parse("a.example.").unwrap()
  let zone = Name::parse("example.").unwrap()
  assert_true(a.is_subdomain(zone))
  assert_true(a.canonical_compare(b) > 0)
  assert_eq(Name::from_wire(a.wire()), Ok(a))
  assert_eq(a.parent(), Some(zone))
  assert_true(Name::parse("relative") is Err(_))
  assert_true(Name::parse("x..example.") is Err(_))
  assert_true(Name::from_wire(b"\xc0\x00") is Err(_))
  assert_true(Name::from_wire(b"\x01a") is Err(_))
  assert_eq(a.signed_owner(1).unwrap(), Name::parse("*.example.").unwrap())
  assert_true(a.signed_owner(3) is Err(_))
}
