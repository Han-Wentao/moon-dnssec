///|
fn trust() -> @dns.TrustedKeys {
  let zone = @dns.Name::parse("example.").unwrap()
  let key = @dns.Dnskey::parse(
    b"\x01\x01\x03\x0f\x26\xcf\xcd\x3b\x19\x35\xd0\x89\x7e\x65\x40\x0d\x1d\xd8\x66\x5b\xc9\x5f\x21\xb7\x63\x74\x9f\xd4\x21\xc1\x2d\x57\xcf\x97\x61\xb7",
  ).unwrap()
  let rr = @dns.Record::new(zone, 48, 60U, key.rdata()).unwrap()
  let sig = @dns.Rrsig::parse(
    b"\x00\x30\x0f\x01\x00\x00\x00\x3c\x00\x00\x00\xc8\x00\x00\x00\x64\x93\x47\x07\x65\x78\x61\x6d\x70\x6c\x65\x00\xc7\xa7\x4b\x37\x28\x94\xe1\x1f\x8e\x15\x5e\xe9\x16\x53\x3e\xd2\xa8\x7a\x5e\x99\xda\x50\x29\x4a\xa6\x66\xfb\x57\x0b\x57\x83\x2e\x2e\x67\x1b\x30\xd7\xcb\x64\x32\xef\x7d\x43\x93\xf0\x66\x7c\x8c\xf0\xc9\xc0\x1a\x75\x4e\xe5\xb5\x14\xc7\x51\xa2\xcc\xad\xcc\x08",
  ).unwrap()
  @dns.anchor_keys(
    zone,
    key,
    [rr],
    [sig],
    @dns.TimePolicy::at(150U),
    @dns.Limits::default(),
  ).unwrap()
}

///|
test "public consumer authenticates signed NSEC and rejects tampering before proof" {
  let keys = trust()
  let zone = keys.zone()
  let rr = @dns.Record::new(
    zone, 47, 60U, b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x00\x00\x07\x22\x00\x00\x00\x00\x03\x80",
  ).unwrap()
  let sig = @dns.Rrsig::parse(
    b"\x00\x2f\x0f\x01\x00\x00\x00\x3c\x00\x00\x00\xc8\x00\x00\x00\x64\x93\x47\x07\x65\x78\x61\x6d\x70\x6c\x65\x00\x1b\x4c\x23\x67\x6a\x7f\xcb\x1e\xdd\x79\xd0\x10\x09\x3f\x0f\x46\x6c\xfa\x52\x80\xd5\xb0\x49\x91\x2c\xb5\xfc\x2f\xc5\x8c\x2f\x5b\x9e\xba\x48\xac\x43\xab\xab\xa9\x0a\xaf\xe1\x10\x1d\x86\x3c\xa6\x9c\xd4\x79\x0a\x17\x9d\xe4\xc3\x84\x4d\x5c\x99\x5c\xe0\xa8\x03",
  ).unwrap()
  let set = @dns.authenticate_rrset(
    [rr],
    [sig],
    keys,
    @dns.TimePolicy::at(150U),
    @dns.Limits::default(),
  ).unwrap()
  let missing = @dns.Name::parse("missing.example.").unwrap()
  assert_eq(
    @dns.nsec_nxdomain([set], zone, missing, 160U, @dns.Limits::default())
    .unwrap()
    .verdict(),
    @dns.Secure,
  )
  assert_eq(
    @dns.nsec_nodata(set, zone, zone, 28, 160U).unwrap().kind(),
    @dns.NoData,
  )
  assert_true(@dns.nsec_nodata(set, zone, zone, 2, 160U) is Err(@dns.Bogus(_)))
  let bad = @dns.Record::new(zone, 47, 60U, b"\x00\x00\x01\x80").unwrap()
  assert_true(
    @dns.authenticate_rrset(
      [bad],
      [sig],
      keys,
      @dns.TimePolicy::at(150U),
      @dns.Limits::default(),
    )
    is Err(_),
  )
}

///|
test "public consumer authenticates signed NSEC3 and enforces fresh proof closure" {
  let keys = trust()
  let zone = keys.zone()
  let rr = @dns.Record::new(
    @dns.Name::parse("3msev9usmd4br9s97v51r2tdvmr9iqo1.example.").unwrap(),
    50,
    60U,
    b"\x01\x00\x00\x00\x00\x14\x1d\xb8\xef\xa7\xdc\xb3\x48\xbd\xa7\x89\x3f\xca\x1d\x8b\xad\xfd\xb6\x99\x6b\x01\x00\x07\x22\x00\x00\x00\x00\x02\x80",
  ).unwrap()
  let sig = @dns.Rrsig::parse(
    b"\x00\x32\x0f\x02\x00\x00\x00\x3c\x00\x00\x00\xc8\x00\x00\x00\x64\x93\x47\x07\x65\x78\x61\x6d\x70\x6c\x65\x00\x4c\xea\x1d\xb7\x3c\xca\xf1\x21\x44\x81\x33\xb9\xdd\x2d\x1f\x84\x72\xac\xfb\x70\x55\xbc\xc9\x7b\x36\xa6\xd0\x33\xf0\x2c\x34\xb1\x75\x01\xeb\x4f\x63\xaa\x1e\xfc\x29\x98\x00\x40\xbf\x47\x14\x2b\x33\x63\xd1\xc9\xdb\x38\x75\x84\x66\x1a\x61\x32\x12\x4c\x33\x01",
  ).unwrap()
  let set = @dns.authenticate_rrset(
    [rr],
    [sig],
    keys,
    @dns.TimePolicy::at(150U),
    @dns.Limits::default(),
  ).unwrap()
  let missing = @dns.Name::parse("missing.example.").unwrap()
  assert_eq(
    @dns.nsec3_nxdomain([set], zone, missing, 160U, @dns.Limits::default())
    .unwrap()
    .kind(),
    @dns.NxDomain,
  )
  assert_true(
    @dns.nsec3_nxdomain([set], zone, missing, 200U, @dns.Limits::default())
    is Err(@dns.Stale(_)),
  )
  assert_true(
    @dns.nsec3_nxdomain([], zone, missing, 160U, @dns.Limits::default())
    is Err(_),
  )
}
