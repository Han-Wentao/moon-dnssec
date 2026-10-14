///|
fn wb_nsec3(
  name : Name,
  zone : Name,
  flags : Int32,
  bitmap : Bytes,
) -> AuthenticatedSet {
  let hash = nsec3_hash(name, b"", 0, Limits::default()).unwrap()
  let owner = Name::parse(
    nsec3_label(hash).unwrap() + "." + zone.host_text().unwrap(),
  ).unwrap()
  let out : Array[Byte] = [1, flags.to_byte(), 0, 0, 0, 20]
  append_bytes(out, hash)
  append_bytes(out, bitmap)
  let rr = Record::new(owner, 50, 60U, Bytes::from_array(out)).unwrap()
  { records: [rr], zone, verified_at: 100U, lifetime: 60U, wildcard: false, }
}

///|
test "NSEC3 exact absence checks owner hash and bitmap" {
  let zone = Name::parse("example.").unwrap()
  let name = Name::parse("child.example.").unwrap()
  let proof = wb_nsec3(name, zone, 0, b"\x00\x01\x40")
  assert_eq(
    nsec3_nodata(proof, zone, name, 28, 110U, Limits::default()).unwrap().kind(),
    NoData,
  )
  assert_true(
    nsec3_nodata(proof, zone, name, 1, 110U, Limits::default()) is Err(Bogus(_)),
  )
  assert_true(
    nsec3_nodata(proof, zone, zone, 28, 110U, Limits::default())
    is Err(Indeterminate(_)),
  )
  let cut = wb_nsec3(name, zone, 1, b"\x00\x01\x20")
  assert_eq(
    nsec3_nodata(cut, zone, name, 43, 110U, Limits::default())
    .unwrap()
    .verdict(),
    Insecure,
  )
  let invalid = wb_nsec3(name, zone, 2, b"")
  assert_true(
    nsec3_nodata(invalid, zone, name, 28, 110U, Limits::default())
    is Err(Malformed(_)),
  )
}
