///|
test "DNSKEY and DS reject truncated and forbidden key forms" {
  assert_true(Dnskey::parse(b"\x01\x00\x03\x0f\x01") is Ok(_))
  assert_true(Dnskey::parse(b"\x01\x80\x03\x0f\x01") is Err(_))
  assert_true(Dnskey::parse(b"\x00\x00\x03\x0f\x01") is Err(_))
  assert_true(Dnskey::parse(b"\x01\x00\x02\x0f\x01") is Err(_))
  assert_true(Ds::parse(b"\x00\x01\x0f\x02\x00") is Err(_))
  let unknown = Ds::parse(b"\x00\x01\x0f\xff\x00").unwrap()
  assert_eq(unknown.rdata(), b"\x00\x01\x0f\xff\x00")
  assert_true(!supported_algorithm(5))
  assert_true(supported_algorithm(15))
}
