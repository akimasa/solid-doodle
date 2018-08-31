extern crate openssl;
use openssl::symm::{encrypt, Cipher};
extern crate hexdump;
use hexdump::hexdump;
use std::io::{BufWriter, Write, SeekFrom, Seek};
use std::fs::OpenOptions;

fn main() {

    println!("Hello, world!");

    let blk = get_block(1,5);
    hexdump(&blk);

    let mut file = OpenOptions::new().read(true).write(true).create(true).open("testfile.bin").expect("open file error");
    let endpos = file.seek(SeekFrom::End(0)).expect("seek error") as usize;
    file.seek(SeekFrom::Start(0)).expect("seek error2");
    let mut fwriter = BufWriter::new(file);
    println!("{}", endpos);
    fwriter.write(&blk).unwrap();
    let mut pos: usize = 0;
    let mut blocks: usize = 0;
    while endpos > pos + 16 {
        blocks = (endpos - pos) / 16;
        if blocks > 1000 {
            blocks = 1000;
        }
        // println!("blocks:{}", blocks);
        if blocks == 0 {
            break;
        }
        let blk = get_block(pos/16,blocks);
        fwriter.write(&blk).unwrap();
        pos += blocks * 16;
    }
    println!("pos,endpos:{},{}", pos,endpos);
    if endpos > pos {
        let blk = get_block(pos/16,1);
        fwriter.write(&blk[0..(endpos-pos)]).unwrap();
    }
    println!("pos,endpos:{},{}", pos,endpos);
}

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
let key = b"\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
let iv = b"\x01\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
for i in 0..len {
    let blk = u64_to_u8_arr((i+init) as u64);
    for j in 0..16 {
        data[i*16+j] = blk[j];
    }
}
// hexdump(&data);
let mut ciphertext = encrypt(
    cipher,
    key,
    Some(iv),
    &data).unwrap();
    ciphertext.truncate(len*16);
    return ciphertext;
}