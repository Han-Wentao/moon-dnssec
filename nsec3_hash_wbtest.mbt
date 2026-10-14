///|
test "NSEC3 repeated hash agrees with independent OpenSSL SHA1" {
  let name = Name::parse("EXAMPLE.").unwrap()
  let hash = nsec3_hash(name, b"\xaa\xbb\xcc\xdd", 12, Limits::default()).unwrap()
  assert_eq(
    hash, b"\x06\x53\x68\xab\xee\xd7\xec\x6e\x9f\xeb\xa9\x6b\x8c\x8b\xc3\xe8\xb7\x91\xf7\x16",
  )
  let label = nsec3_label(hash).unwrap()
  assert_eq(
    decode_nsec3_label(Name::parse(label + ".example.").unwrap().labels[0]),
    Ok(hash),
  )
  assert_true(
    nsec3_hash(name, b"", 101, Limits::default()) is Err(ResourceLimit(_)),
  )
  assert_true(decode_nsec3_label(b"short") is Err(_))
  assert_true(decode_nsec3_label(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") is Err(_))
}
