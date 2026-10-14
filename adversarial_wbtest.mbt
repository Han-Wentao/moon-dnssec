///|
test "all truncated RRSIG prefixes fail boundedly before crypto" {
  let sig : Rrsig = {
    covered: 1,
    algorithm: 15,
    labels: 1,
    original_ttl: 60U,
    inception: 100U,
    expiration: 200U,
    key_tag: 1,
    signer: Name::parse("example.").unwrap(),
    signature: b"s",
  }
  let wire = sig.rdata()
  for n = 0; n < wire.length(); n = n + 1 {
    assert_true(Rrsig::parse(wire[:n].to_owned()) is Err(_))
  }
}

///|
test "canonical name boundary and binary labels preserve DNS bytes" {
  let labels = String::make(63, 'a')
  assert_true(
    Name::parse(
      labels + "." + labels + "." + labels + "." + String::make(61, 'b') + ".",
    )
    is Ok(_),
  )
  assert_true(
    Name::parse(
      labels + "." + labels + "." + labels + "." + String::make(62, 'b') + ".",
    )
    is Err(_),
  )
  assert_true(Name::parse(String::make(64, 'a') + ".") is Err(_))
  let binary = Name::from_wire(b"\x03\x00AZ\x00").unwrap()
  assert_eq(binary.wire(), b"\x03\x00az\x00")
  assert_true(binary.host_text() is Err(Unsupported(_)))
}

///|
test "all configured resource policy dimensions have hard ceilings" {
  let good = Limits::default()
  assert_true({ ..good, max_records: 4097, }.validate() is Err(_))
  assert_true({ ..good, max_signed_bytes: 16777217, }.validate() is Err(_))
  assert_true({ ..good, max_signatures: 129, }.validate() is Err(_))
  assert_true({ ..good, max_proofs: 257, }.validate() is Err(_))
  assert_true({ ..good, max_chain: 65, }.validate() is Err(_))
  assert_true({ ..good, max_nsec3_iterations: 501, }.validate() is Err(_))
}

///|
test "NSEC interval excludes endpoints and covers wrap correctly" {
  let zone = Name::parse("example.").unwrap()
  let a = Name::parse("a.example.").unwrap()
  let z = Name::parse("z.example.").unwrap()
  let rr = wb_nsec(z, a, b"\x00\x06\x40\x00\x00\x00\x00\x03", zone).records[0]
  let nsec = Nsec::parse(rr).unwrap()
  assert_true(!nsec.covers(a))
  assert_true(!nsec.covers(z))
  assert_true(nsec.covers(zone))
  assert_true(!nsec.covers(Name::parse("m.example.").unwrap()))
}

///|
test "aliases and wildcard expansions cannot become authenticated denial" {
  let zone = Name::parse("example.").unwrap()
  let proof = wb_nsec(zone, zone, b"\x00\x06\x04\x00\x00\x00\x00\x03", zone)
  assert_true(nsec_nodata(proof, zone, zone, 28, 110U) is Err(Bogus(_)))
  assert_true(
    nsec_nxdomain(
      [proof],
      zone,
      Name::parse("x.example.").unwrap(),
      110U,
      Limits::default(),
    )
    is Err(Indeterminate(_)),
  )
  assert_true(
    nsec_nodata({ ..proof, wildcard: true, }, zone, zone, 28, 110U)
    is Err(Bogus(_)),
  )
}
