//! Common age-independent OSPF LSA Fletcher checksum.
pub(crate) fn insert(out: &mut [u8]) {
    let (c0, c1) = fletcher(&out[2..]);
    let mut x = ((out.len() as i64 - 17) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    out[16] = x as u8;
    out[17] = y as u8;
}
pub(crate) fn fletcher(bytes: &[u8]) -> (i64, i64) {
    bytes.iter().fold((0, 0), |(c0, c1), byte| {
        let c0 = (c0 + i64::from(*byte)) % 255;
        (c0, (c1 + c0) % 255)
    })
}
