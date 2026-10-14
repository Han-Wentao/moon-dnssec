///|
fn wb_nsec(
  owner : Name,
  next : Name,
  bitmap : Bytes,
  zone : Name,
) -> AuthenticatedSet {
  let out : Array[Byte] = []
  append_bytes(out, next.wire())
  append_bytes(out, bitmap)
  let rr = Record::new(owner, 47, 60U, Bytes::from_array(out)).unwrap()
  { records: [rr], zone, verified_at: 100U, lifetime: 60U, wildcard: false, }
}

///|
test "authenticated NSEC distinguishes NODATA and insecure delegation" {
  let zone = Name::parse("example.").unwrap()
  let name = Name::parse("child.example.").unwrap()
  let normal = wb_nsec(name, zone, b"\x00\x06\x40\x00\x00\x00\x00\x03", zone)
  assert_eq(nsec_nodata(normal, zone, name, 28, 110U).unwrap().kind(), NoData)
  assert_true(nsec_nodata(normal, zone, name, 1, 110U) is Err(Bogus(_)))
  let delegation = wb_nsec(
    name, zone, b"\x00\x06\x20\x00\x00\x00\x00\x03", zone,
  )
  assert_eq(
    nsec_nodata(delegation, zone, name, 43, 110U).unwrap().verdict(),
    Insecure,
  )
  assert_true(
    nsec_nodata(delegation, zone, name, 28, 110U) is Err(Indeterminate(_)),
  )
  assert_true(nsec_nodata(normal, zone, name, 28, 160U) is Err(Stale(_)))
}
