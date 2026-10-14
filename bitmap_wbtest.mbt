///|
test "type bitmaps enforce ordered minimal windows" {
  let data = b"\x00\x06\x40\x00\x00\x00\x00\x03\xff\x01\x80"
  let bitmap = TypeBitmap::parse(data).unwrap()
  assert_true(bitmap.contains(1))
  assert_true(bitmap.contains(46))
  assert_true(bitmap.contains(47))
  assert_true(bitmap.contains(65280))
  assert_eq(bitmap.encode(), data)
  assert_true(TypeBitmap::parse(b"\x00\x01\x00") is Err(_))
  assert_true(TypeBitmap::parse(b"\x00\x01\x80\x00\x01\x80") is Err(_))
  assert_true(TypeBitmap::parse(b"\x00\x21") is Err(_))
  assert_eq(TypeBitmap::parse(b"").unwrap().types(), [])
}
