extern crate chrono;
extern crate openssl;

use std::env;

use chrono::prelude::*;
use openssl::symm::{encrypt, Cipher};

const FLD_DIGIT_SHIFT: u8 = 6;
const FLD_DIGIT_MASK: u16 = (0b111 << FLD_DIGIT_SHIFT);

fn main() {
    let serial = env::var("RSA_AUTH_SERIAL").unwrap();
    let seed: Vec<u8> = env::var("RSA_AUTH_SEED").unwrap().split(':').map(|x| u8::from_str_radix(x, 16).unwrap()).collect();

    let time = Utc::now();
    let bcd_time = bcd_time(time);

    let mut key0 = [0; 16];
    let mut key1 = [0; 16];

    key_from_time(bcd_time, 2, &serial, &mut key0);
    aes128_ecb_encrypt(&mut key0, seed.as_slice());

    key_from_time(bcd_time, 3, &serial, &mut key1);
    aes128_ecb_encrypt(&mut key1, &key0);

    key_from_time(bcd_time, 4, &serial, &mut key0);
    aes128_ecb_encrypt(&mut key0, &key1);

    key_from_time(bcd_time, 5, &serial, &mut key1);
    aes128_ecb_encrypt(&mut key1, &key0);

    key_from_time(bcd_time, 8, &serial, &mut key0);
    aes128_ecb_encrypt(&mut key0, &key1);

    let mut i = ((time.minute() as usize) & 0b11) << 2;
    let t1 = ((key0[i + 0] as u32) & 0xff) << 24;
    let t2 = ((key0[i + 1] as u32) & 0xff) << 16;
    let t3 = ((key0[i + 2] as u32) & 0xff) << 8;
    let t4 = ((key0[i + 3] as u32) & 0xff) << 0;
    let mut token_code = t1 | t2 | t3 | t4;

    let mut out = vec![];
    let mut j: isize = ((17369 & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) as isize;
    while j >= 0 {
        let mut c = (token_code % 10) as u8;
        token_code /= 10;

        if i < 8 {
            c += 0;
        }
        out.push(c % 10);

        j -= 1;
        i += 1;
    }

    println!("{}", out.iter().rev().map(|x| (x + b'0') as char).collect::<String>());
}

fn aes128_ecb_encrypt(input: &mut [u8; 16], key: &[u8]) {
    let cipher = Cipher::aes_128_ecb();
    let output = encrypt(cipher, key, None, input).unwrap();
    for i in 0..16 {
        input[i] = output[i];
    }
}

#[test]
fn test_key_from_time() {
    let serial = "356269991449";
    let time = Utc.ymd(2020, 1, 10).and_hms(0, 4, 0);
    let bcd_time = bcd_time(time);

    let mut key0 = [0; 16];
    key_from_time(bcd_time, 2, &serial, &mut key0);

    assert_eq!(
        key0,
        [32, 32, 170, 170, 170, 170, 170, 170, 105, 153, 20, 73, 187, 187, 187, 187,]
    );
}

fn key_from_time(bcd_time: [u8; 8], bcd_time_bytes: usize, serial: &str, key: &mut [u8; 16]) {
    for i in 0..8 {
        key[i] = 0xaa;
    }
    for i in 12..key.len() {
        key[i] = 0xbb;
    }
    for i in 0..bcd_time_bytes {
        key[i] = bcd_time[i];
    }

    let serial: Vec<_> = serial.chars().map(|c| c.to_digit(10).unwrap() as u8).collect();

    let mut k = 8;
    let mut i = 4;
    while i < 12 {
        key[k] = (serial[i] << 4) | serial[i + 1];
        k += 1;
        i += 2;
    }
}

#[test]
fn test_bcd_time() {
    let time = Utc.ymd(2020, 1, 9).and_hms(23, 23, 0);
    let bcd_time = bcd_time(time);

    assert_eq!(bcd_time, [32, 32, 1, 9, 35, 32, 0, 0]);
}

fn bcd_time(time: DateTime<Utc>) -> [u8; 8] {
    let mut bcd_time = [0; 8];

    bcd_write(&mut bcd_time[0..=1], time.year() as u16);
    bcd_write(&mut bcd_time[2..3], time.month() as u16);
    bcd_write(&mut bcd_time[3..4], time.day() as u16);
    bcd_write(&mut bcd_time[4..5], time.hour() as u16);
    bcd_write(&mut bcd_time[5..6], (time.minute() & !0b11) as u16);

    bcd_time
}

fn bcd_write(out: &mut [u8], mut val: u16) {
    for v in out {
        *v = bcd_offset(&mut val);
    }
}

fn bcd_offset(val: &mut u16) -> u8 {
    let mut out = (*val % 10) as u8;
    *val /= 10;
    out |= ((*val % 10) as u8) << 4;
    *val /= 10;

    out
}