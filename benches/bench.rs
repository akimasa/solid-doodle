#![feature(test)]

extern crate test;

extern crate openssl;
use openssl::symm::{encrypt, Cipher};

pub fn add_two(a: i32) -> i32 {
    a + 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
fn u64_to_u8_arr(x:u64) -> [u8;16] {
    let b1 : u8 = ((x >> 56) & 0xff) as u8;
    let b2 : u8 = ((x >> 48) & 0xff) as u8;
    let b3 : u8 = ((x >> 40) & 0xff) as u8;
    let b4 : u8 = ((x >> 32) & 0xff) as u8;
    let b5 : u8 = ((x >> 24) & 0xff) as u8;
    let b6 : u8 = ((x >> 16) & 0xff) as u8;
    let b7 : u8 = ((x >> 8) & 0xff) as u8;
    let b8 : u8 = (x & 0xff) as u8;
    return [0, 0, 0, 0, 0, 0, 0, 0, b1, b2, b3, b4, b5, b6, b7, b8];
}

fn get_block(init:usize, len:usize) -> Vec<u8> {
        let cipher = Cipher::aes_128_ecb();
let mut data = vec![0; len*16];
let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
let iv = b"\x01\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
for i in 0..len {
    let blk = u64_to_u8_arr((i+init) as u64);
    for j in 0..16 {
        data[i*16+j] = blk[j];
    }
}
let ciphertext = encrypt(
    cipher,
    key,
    Some(iv),
    &data).unwrap();
    return ciphertext;
}
    #[test]
    fn it_works() {
        assert_eq!(4, add_two(2));
    }

    #[bench]
    fn bench_block1000k(b: &mut Bencher) {
        b.iter(|| get_block(1,1000*1000));
    }
    #[bench]
    fn bench_block1000(b: &mut Bencher) {
        b.iter(|| get_block(1,1000));
    }
}