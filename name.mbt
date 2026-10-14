///|
/// Canonical uncompressed name. Construction checks wire size and label size.
pub struct Name {
  labels : Array[Bytes]
} derive(Eq, Debug)

///|
pub extend Name with Eq::{equal, not_equal}

///|
pub extend Name with @debug.Debug::{to_repr}

///|
pub fn Name::parse(text : String) -> Result[Name, DnsError] {
  if text == "." {
    return Ok({ labels: [], })
  }
  if !text.has_suffix(".") {
    return Err(Malformed("presentation names must be absolute"))
  }
  let labels : Array[Bytes] = []
  let mut size = 1
  for part in text[:text.length() - 1].split(".") {
    let bytes : Array[Byte] = []
    for c in part.iter() {
      let n = c.to_int()
      if n < 33 || n > 126 || n == 92 {
        return Err(
          Unsupported("use wire names for escaped or non-ASCII labels"),
        )
      }
      bytes.push((if n >= 65 && n <= 90 { n + 32 } else { n }).to_byte())
    }
    if bytes.length() == 0 || bytes.length() > 63 {
      return Err(Malformed("label size outside 1..63"))
    }
    size += 1 + bytes.length()
    if size > 255 {
      return Err(Malformed("name exceeds 255 wire bytes"))
    }
    labels.push(Bytes::from_array(bytes))
  }
  Ok({ labels, })
}

///|
fn read_name(data : Bytes, start : Int) -> Result[(Name, Int), DnsError] {
  if start < 0 || start >= data.length() {
    return Err(Malformed("missing name"))
  }
  let labels : Array[Bytes] = []
  let mut p = start
  while p < data.length() {
    let n = data[p].to_int()
    p += 1
    if n == 0 {
      if p - start > 255 {
        return Err(Malformed("name too long"))
      }
      return Ok(({ labels, }, p))
    }
    if n > 63 {
      return Err(Malformed("compressed or reserved label"))
    }
    if p + n > data.length() || p + n - start > 254 {
      return Err(Malformed("truncated or oversized name"))
    }
    let label : Array[Byte] = []
    for i = p; i < p + n; i = i + 1 {
      let b = data[i].to_int()
      label.push((if b >= 65 && b <= 90 { b + 32 } else { b }).to_byte())
    }
    labels.push(Bytes::from_array(label))
    p += n
  }
  Err(Malformed("unterminated name"))
}

///|
pub fn Name::from_wire(data : Bytes) -> Result[Name, DnsError] {
  match read_name(data, 0) {
    Err(e) => Err(e)
    Ok((name, end)) =>
      if end == data.length() {
        Ok(name)
      } else {
        Err(Malformed("trailing name bytes"))
      }
  }
}

///|
pub fn Name::wire(self : Name) -> Bytes {
  let out : Array[Byte] = []
  for label in self.labels {
    out.push(label.length().to_byte())
    for b in label {
      out.push(b)
    }
  }
  out.push(0)
  Bytes::from_array(out)
}

///|
pub fn Name::label_count(self : Name) -> Int {
  self.labels.length()
}

///|
pub fn Name::is_subdomain(self : Name, zone : Name) -> Bool {
  if self.labels.length() < zone.labels.length() {
    return false
  }
  let offset = self.labels.length() - zone.labels.length()
  for i = 0; i < zone.labels.length(); i = i + 1 {
    if self.labels[offset + i] != zone.labels[i] {
      return false
    }
  }
  true
}

///|
/// RFC4034 rightmost-label order, not presentation string order.
pub fn Name::canonical_compare(self : Name, other : Name) -> Int {
  let mut a = self.labels.length() - 1
  let mut b = other.labels.length() - 1
  while a >= 0 && b >= 0 {
    let c = bytes_compare(self.labels[a], other.labels[b])
    if c != 0 {
      return c
    }
    a -= 1
    b -= 1
  }
  if a < b {
    -1
  } else if a > b {
    1
  } else {
    0
  }
}

///|
pub fn Name::parent(self : Name) -> Name? {
  if self.labels.is_empty() {
    return None
  }
  Some({ labels: self.labels[1:].to_owned(), })
}

///|
fn Name::wildcard(self : Name) -> Result[Name, DnsError] {
  if self.wire().length() + 2 > 255 {
    return Err(Malformed("wildcard name too long"))
  }
  let labels = [b"*"]
  for l in self.labels {
    labels.push(l)
  }
  Ok({ labels, })
}

///|
pub fn Name::signed_owner(self : Name, labels : Int) -> Result[Name, DnsError] {
  if labels < 0 || labels > self.labels.length() {
    return Err(Bogus("RRSIG labels exceed owner labels"))
  }
  if labels == self.labels.length() {
    return Ok(self)
  }
  let tail : Name = {
    labels: self.labels[self.labels.length() - labels:].to_owned(),
  }
  tail.wildcard()
}

///|
fn bytes_compare(a : Bytes, b : Bytes) -> Int {
  for i = 0; i < a.length() && i < b.length(); i = i + 1 {
    if a[i] < b[i] {
      return -1
    }
    if a[i] > b[i] {
      return 1
    }
  }
  if a.length() < b.length() {
    -1
  } else if a.length() > b.length() {
    1
  } else {
    0
  }
}
