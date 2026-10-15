//! Input layout shared by the fuzz targets and the corpus generator.
//!
//! `[selector: u8] [len_a: u16 LE] [a] [len_b: u16 LE] [b] [rest]`
//!
//! Every byte string is a valid input: missing bytes make the remaining fields shorter or
//! empty, and a length longer than what is left takes what is left. The lengths are explicit so
//! that the fuzzer can try wrong lengths as easily as right ones.

pub struct Fields<'a> {
    pub selector: u8,
    pub a: &'a [u8],
    pub b: &'a [u8],
    pub rest: &'a [u8],
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let n = n.min(data.len());
    let (head, tail) = data.split_at(n);
    *data = tail;
    head
}

fn take_len(data: &mut &[u8]) -> usize {
    let b = take(data, 2);
    match b {
        [lo, hi] => usize::from(u16::from_le_bytes([*lo, *hi])),
        [lo] => usize::from(*lo),
        _ => 0,
    }
}

pub fn split(mut data: &[u8]) -> Fields<'_> {
    let selector = take(&mut data, 1).first().copied().unwrap_or(0);
    let len_a = take_len(&mut data);
    let a = take(&mut data, len_a);
    let len_b = take_len(&mut data);
    let b = take(&mut data, len_b);
    Fields {
        selector,
        a,
        b,
        rest: data,
    }
}

pub fn join(selector: u8, a: &[u8], b: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut out = vec![selector];
    out.extend_from_slice(&u16::try_from(a.len()).unwrap().to_le_bytes());
    out.extend_from_slice(a);
    out.extend_from_slice(&u16::try_from(b.len()).unwrap().to_le_bytes());
    out.extend_from_slice(b);
    out.extend_from_slice(rest);
    out
}

/// FIPS 203 section 7.2, written independently of ml-kem: an encapsulation key is valid when it
/// has the right length and every 12-bit coefficient of its first 384 * k bytes is below q.
pub fn ek_is_valid(k: usize, ek: &[u8]) -> bool {
    if ek.len() != 384 * k + 32 {
        return false;
    }
    ek[..384 * k].chunks(3).all(|t| {
        let a = u16::from(t[0]) | (u16::from(t[1] & 0x0f) << 8);
        let b = u16::from(t[1] >> 4) | (u16::from(t[2]) << 4);
        a < 3329 && b < 3329
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_inverts_join() {
        let data = join(7, b"abc", b"", b"rest");
        let f = split(&data);
        assert_eq!((f.selector, f.a, f.b, f.rest), (7, &b"abc"[..], &b""[..], &b"rest"[..]));
        let f = split(&[]);
        assert_eq!((f.selector, f.a.len(), f.b.len(), f.rest.len()), (0, 0, 0, 0));
        let f = split(&[1, 0xff, 0xff, 9]);
        assert_eq!((f.selector, f.a, f.b.len()), (1, &[9u8][..], 0));
    }
}
