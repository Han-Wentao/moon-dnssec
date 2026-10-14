///|
test "canonical SOA SRV and name types preserve numeric data and lowercase names" {
  let zone = Name::parse("example.").unwrap()
  for t in [2, 5, 12, 39] {
    let rr = Record::new(zone, t, 1U, b"\x02NS\x07EXAMPLE\x00").unwrap()
    assert_eq(rr.canonical_rdata(), Ok(b"\x02ns\x07example\x00"))
  }
  let srv = Record::new(zone, 33, 1U, b"\x00\x01\x00\x02\x00\x03\x02NS\x00").unwrap()
  assert_eq(srv.canonical_rdata(), Ok(b"\x00\x01\x00\x02\x00\x03\x02ns\x00"))
  let soa_data : Array[Byte] = []
  append_bytes(soa_data, b"\x02NS\x00\x04MAIL\x00")
  for i = 0; i < 5; i = i + 1 {
    append32(soa_data, i.reinterpret_as_uint())
  }
  let soa = Record::new(zone, 6, 1U, Bytes::from_array(soa_data)).unwrap()
  assert_eq(soa.canonical_rdata().unwrap().length(), 30)
  assert_true(
    Record::new(zone, 6, 1U, b"\x00\x00").unwrap().canonical_rdata() is Err(_),
  )
  assert_eq(
    Record::new(zone, 16, 1U, b"\x00\x02hi").unwrap().canonical_rdata(),
    Ok(b"\x00\x02hi"),
  )
  assert_true(
    Record::new(zone, 28, 1U, b"short").unwrap().canonical_rdata() is Err(_),
  )
  assert_true(Record::new(zone, 41, 1U, b"") is Err(_))
  assert_true(Record::new(zone, 65536, 1U, b"") is Err(_))
}

///|
test "signature matching empty candidates and skew policies fail predictably" {
  let zone = Name::parse("example.").unwrap()
  let key = Dnskey::parse(b"\x01\x01\x03\x0f\x01").unwrap()
  let rr = Record::new(zone, 1, 60U, b"1234").unwrap()
  let sig : Rrsig = {
    covered: 1,
    algorithm: 15,
    labels: 1,
    original_ttl: 60U,
    inception: 100U,
    expiration: 200U,
    key_tag: key.key_tag(zone).unwrap(),
    signer: zone,
    signature: b"s",
  }
  assert_eq(sig.remaining({ now: 99U, skew: 1U, }), Ok(100U))
  assert_true(sig.remaining(TimePolicy::at(99U)) is Err(Stale(_)))
  assert_true(
    sig.remaining({ now: 100U, skew: 3601U, }) is Err(ResourceLimit(_)),
  )
  assert_true(
    authenticate_with_key(
      [rr],
      [],
      zone,
      key,
      TimePolicy::at(150U),
      Limits::default(),
    )
    is Err(Indeterminate(_)),
  )
  assert_true(
    authenticate_with_key([rr], [sig, sig], zone, key, TimePolicy::at(150U), {
      ..Limits::default(),
      max_signatures: 1,
    })
    is Err(ResourceLimit(_)),
  )
  assert_true(
    authenticate_with_key(
      [rr],
      [{ ..sig, key_tag: 0, }],
      zone,
      key,
      TimePolicy::at(150U),
      Limits::default(),
    )
    is Err(Indeterminate(_)),
  )
  assert_true(
    authenticate_with_key(
      [rr],
      [sig],
      zone,
      key,
      TimePolicy::at(150U),
      Limits::default(),
    )
    is Err(Malformed(_)),
  )
}

///|
test "signing input enforces type signer owner and allocation contracts" {
  let zone = Name::parse("example.").unwrap()
  let rr = Record::new(zone, 1, 60U, b"1234").unwrap()
  let sig : Rrsig = {
    covered: 1,
    algorithm: 15,
    labels: 1,
    original_ttl: 60U,
    inception: 100U,
    expiration: 200U,
    key_tag: 1,
    signer: zone,
    signature: b"s",
  }
  assert_true(
    signing_input([rr], { ..sig, covered: 28, }, Limits::default())
    is Err(Bogus(_)),
  )
  assert_true(
    signing_input([rr], { ..sig, labels: 2, }, Limits::default())
    is Err(Bogus(_)),
  )
  assert_true(
    signing_input(
      [rr],
      { ..sig, signer: Name::parse("other.").unwrap(), },
      Limits::default(),
    )
    is Err(Bogus(_)),
  )
  assert_true(
    signing_input(
      [
        rr,
        Record::new(Name::parse("other.").unwrap(), 1, 60U, b"1234").unwrap(),
      ],
      sig,
      Limits::default(),
    )
    is Err(Malformed(_)),
  )
  let huge = Record::new(
    zone,
    65280,
    1U,
    Bytes::from_array(Array::make(256, 0)),
  ).unwrap()
  assert_true(
    signing_input([huge], { ..sig, covered: 65280, }, {
      ..Limits::default(),
      max_signed_bytes: 255,
    })
    is Err(ResourceLimit(_)),
  )
}

///|
test "DS mismatches and unsupported keys cannot become trust" {
  let zone = Name::parse("example.").unwrap()
  let key = Dnskey::parse(b"\x01\x01\x03\x0f\x01").unwrap()
  let digest = Bytes::from_array(Array::make(32, 0))
  let ds : Ds = { key_tag: 0, algorithm: 15, digest_type: 2, digest, }
  assert_eq(ds.matches(zone, key), Ok(false))
  assert_eq({ ..ds, algorithm: 13, }.matches(zone, key), Ok(false))
  assert_true(
    verify_signature(
      Dnskey::parse(b"\x01\x01\x03\xff\x01").unwrap(),
      b"x",
      b"x",
    )
    is Err(Unsupported(_)),
  )
  assert_true(
    anchor_keys(zone, key, [], [], TimePolicy::at(150U), Limits::default())
    is Err(_),
  )
  let badrr = Record::new(zone, 1, 60U, b"1234").unwrap()
  assert_true(
    anchor_keys(zone, key, [badrr], [], TimePolicy::at(150U), Limits::default())
    is Err(Malformed(_)),
  )
  let unsupported = Record::new(zone, 48, 60U, b"\x01\x01\x03\xff\x01").unwrap()
  assert_true(
    anchor_keys(
      zone,
      key,
      [unsupported],
      [],
      TimePolicy::at(150U),
      Limits::default(),
    )
    is Err(Indeterminate(_)),
  )
}

///|
test "proof preconditions reject stale wrong-zone meta queries and incomplete bitmaps" {
  let zone = Name::parse("example.").unwrap()
  let proof = wb_nsec(zone, zone, b"\x00\x06\x02\x00\x00\x00\x00\x03", zone)
  assert_true(nsec_nodata(proof, zone, zone, 255, 110U) is Err(Unsupported(_)))
  assert_true(nsec_nodata(proof, zone, zone, 43, 110U) is Err(Indeterminate(_)))
  assert_true(
    proof.denial_record(Name::parse("other.").unwrap(), 47, 110U)
    is Err(Bogus(_)),
  )
  assert_true(proof.denial_record(zone, 1, 110U) is Err(Malformed(_)))
  let incomplete = wb_nsec(zone, zone, b"\x00\x01\x40", zone)
  assert_true(
    nsec_nodata(incomplete, zone, zone, 28, 110U) is Err(Malformed(_)),
  )
  assert_true(
    nsec_nxdomain(
      [],
      zone,
      Name::parse("x.example.").unwrap(),
      110U,
      Limits::default(),
    )
    is Err(ResourceLimit(_)),
  )
}
