///|
/// Strict RFC4034 window bitmap. Empty is allowed for NSEC3 empty nonterminals.
pub struct TypeBitmap {
  types : Array[Int]
} derive(Eq, Debug)

///|
pub extend TypeBitmap with Eq::{equal, not_equal}

///|
pub extend TypeBitmap with @debug.Debug::{to_repr}

///|
pub fn TypeBitmap::parse(data : Bytes) -> Result[TypeBitmap, DnsError] {
  let types : Array[Int] = []
  let mut p = 0
  let mut previous = -1
  while p < data.length() {
    if data.length() - p < 2 {
      return Err(Malformed("truncated bitmap header"))
    }
    let window = data[p].to_int()
    let n = data[p + 1].to_int()
    p += 2
    if window <= previous {
      return Err(Malformed("bitmap windows not strictly ordered"))
    }
    if n < 1 || n > 32 || n > data.length() - p {
      return Err(Malformed("bitmap window length"))
    }
    if data[p + n - 1] == 0 {
      return Err(Malformed("non-minimal bitmap window"))
    }
    for i = 0; i < n; i = i + 1 {
      for bit = 0; bit < 8; bit = bit + 1 {
        if (data[p + i].to_int() & (128 >> bit)) != 0 {
          types.push(window * 256 + i * 8 + bit)
        }
      }
    }
    p += n
    previous = window
  }
  Ok({ types, })
}

///|
pub fn TypeBitmap::contains(self : TypeBitmap, rrtype : Int) -> Bool {
  self.types.contains(rrtype)
}

///|
pub fn TypeBitmap::types(self : TypeBitmap) -> Array[Int] {
  self.types.copy()
}

///|
pub fn TypeBitmap::encode(self : TypeBitmap) -> Bytes {
  let out : Array[Byte] = []
  let mut p = 0
  while p < self.types.length() {
    let window = self.types[p] / 256
    let bits : Array[Byte] = Array::make(32, 0)
    let mut length = 0
    while p < self.types.length() && self.types[p] / 256 == window {
      let t = self.types[p] % 256
      let i = t / 8
      bits[i] = (bits[i].to_int() | (128 >> (t % 8))).to_byte()
      if i + 1 > length {
        length = i + 1
      }
      p += 1
    }
    out.push(window.to_byte())
    out.push(length.to_byte())
    for i = 0; i < length; i = i + 1 {
      out.push(bits[i])
    }
  }
  Bytes::from_array(out)
}
