///|
test "NSEC3 NXDOMAIN does not upgrade opt-out coverage to secure" {
  let zone = Name::parse("example.").unwrap()
  let name = Name::parse("missing.example.").unwrap()
  let proof = wb_nsec3(zone, zone, 0, b"\x00\x01\x02")
  assert_eq(
    nsec3_nxdomain([proof], zone, name, 110U, Limits::default()).unwrap().kind(),
    NxDomain,
  )
  let opt_out = wb_nsec3(zone, zone, 1, b"\x00\x01\x02")
  assert_true(
    nsec3_nxdomain([opt_out], zone, name, 110U, Limits::default())
    is Err(Indeterminate(_)),
  )
  let exists = wb_nsec3(name, zone, 0, b"\x00\x01\x40")
  assert_true(
    nsec3_nxdomain([proof, exists], zone, name, 110U, Limits::default())
    is Err(Bogus(_)),
  )
  assert_true(
    nsec3_nxdomain(
      [proof],
      zone,
      Name::parse("a.b.c.example.").unwrap(),
      110U,
      { ..Limits::default(), max_chain: 2, },
    )
    is Err(ResourceLimit(_)),
  )
}
