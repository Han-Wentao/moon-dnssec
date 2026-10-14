///|
test "NXDOMAIN needs closest encloser plus wildcard and next-closer denial" {
  let zone = Name::parse("example.").unwrap()
  let name = Name::parse("missing.example.").unwrap()
  let apex = wb_nsec(zone, zone, b"\x00\x06\x02\x00\x00\x00\x00\x03", zone)
  let proof = nsec_nxdomain([apex], zone, name, 110U, Limits::default()).unwrap()
  assert_eq(proof.kind(), NxDomain)
  assert_eq(proof.lifetime(), 50U)
  assert_true(
    nsec_nxdomain([apex], zone, zone, 110U, Limits::default()) is Err(Bogus(_)),
  )
  let narrow = wb_nsec(
    zone,
    Name::parse("aaa.example.").unwrap(),
    b"\x00\x06\x02\x00\x00\x00\x00\x03",
    zone,
  )
  assert_true(
    nsec_nxdomain([narrow], zone, name, 110U, Limits::default())
    is Err(Indeterminate(_)),
  )
  let cut = Name::parse("child.example.").unwrap()
  let delegation = wb_nsec(cut, zone, b"\x00\x06\x20\x00\x00\x00\x00\x03", zone)
  assert_true(
    nsec_nxdomain(
      [apex, delegation],
      zone,
      Name::parse("x.child.example.").unwrap(),
      110U,
      Limits::default(),
    )
    is Err(Indeterminate(_)),
  )
}

///|
test "NSEC ancestor traversal obeys configured depth before proof processing" {
  let zone = Name::parse("example.").unwrap()
  let query = Name::parse("a.b.example.").unwrap()
  let apex = wb_nsec(zone, zone, b"\x00\x06\x02\x00\x00\x00\x00\x03", zone)
  let limits = { ..Limits::default(), max_chain: 1, }
  assert_true(
    nsec_nxdomain([apex], zone, query, 110U, limits) is Err(ResourceLimit(_)),
  )
  assert_eq(
    nsec_nxdomain([apex], zone, query, 110U, Limits::default()).unwrap().kind(),
    NxDomain,
  )
}
