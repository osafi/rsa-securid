use bytes::{BufMut, Bytes, BytesMut};
use chrono::prelude::*;
use openssl::symm::{encrypt, Cipher};
use regex::Regex;
use std::convert::TryInto;
use std::str::FromStr;

const FLD_DIGIT_SHIFT: u8 = 6;
const FLD_DIGIT_MASK: u16 = (0b111 << FLD_DIGIT_SHIFT);

pub fn bcd_write(bytes: &mut BytesMut, val: u8) {
    let mut out = val % 10;
    out |= (val / 10 % 10) << 4;
    bytes.put_u8(out);
}

pub struct Token {
    pub serial: Serial,
    pub seed: Vec<u8>,
    pub pin: Vec<u8>,
}

impl Token {
    pub fn code(&self, time: &DateTime<Utc>) -> String {
        let bcd_time = Self::bcd_time(time);

        let key0 = Bytes::from(vec![0; 16]);
        let key1 = Bytes::copy_from_slice(&self.seed);

        let key0 = self.key_from_time(&bcd_time.slice(0..2), &key0);
        let key0 = Self::aes128_ecb_encrypt(&key0, &key1);

        let key1 = self.key_from_time(&bcd_time.slice(0..3), &key1);
        let key1 = Self::aes128_ecb_encrypt(&key1, &key0);

        let key0 = self.key_from_time(&bcd_time.slice(0..4), &key0);
        let key0 = Self::aes128_ecb_encrypt(&key0, &key1);

        let key1 = self.key_from_time(&bcd_time.slice(0..5), &key1);
        let key1 = Self::aes128_ecb_encrypt(&key1, &key0);

        let key0 = self.key_from_time(&bcd_time.slice(0..8), &key0);
        let key0 = Self::aes128_ecb_encrypt(&key0, &key1);

        let mut i = ((time.minute() as usize) & 0b11) << 2;
        let mut token_code = u32::from_be_bytes(key0[i..i+4].try_into().unwrap());

        let mut out = vec![];
        let mut j: isize = ((0b0100001111011001 & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) as isize;
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

        out.iter().rev().map(u8::to_string).collect()
    }

    fn aes128_ecb_encrypt(input: &Bytes, key: &Bytes) -> Bytes {
        let cipher = Cipher::aes_128_ecb();
        let output = encrypt(cipher, key, None, input).unwrap();
        Bytes::from(output).slice(0..16)
    }

    fn key_from_time(&self, bcd_time_slice: &Bytes, key: &Bytes) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.resize(16, 0);

        for i in 0..bytes.capacity() {
            bytes[i] = match i {
                0..=7 => if i < bcd_time_slice.len() { bcd_time_slice[i] } else { 0xaa },
                8..=11 => self.serial.bytes[i - 6],
                12..=15 => 0xbb,
                _ => key[i],
            }
        }

        return bytes.freeze();
    }

    fn bcd_time(time: &DateTime<Utc>) -> Bytes {
        let mut bytes = BytesMut::with_capacity(8);

        bcd_write(&mut bytes, (time.year() % 100) as u8);
        bcd_write(&mut bytes, (time.year() / 100 % 100) as u8);
        bcd_write(&mut bytes, time.month() as u8);
        bcd_write(&mut bytes, time.day() as u8);
        bcd_write(&mut bytes, time.hour() as u8);
        bcd_write(&mut bytes, (time.minute() & !0b11) as u8);
        bytes.put_u8(0);
        bytes.put_u8(0);

        bytes.freeze()
    }
}

pub struct Serial {
    bytes: Bytes,
}

impl FromStr for Serial {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = Regex::new(r"^\d{12}$").unwrap();
        if !re.is_match(&s) {
            return Err("the serial needs to be 12 digits".into());
        }

        let digits: Vec<_> = s.chars().map(|c| c.to_digit(10).unwrap() as u8).collect();

        let mut bytes = BytesMut::with_capacity(6);
        for w in digits.chunks(2) {
            let val = 10 * w[0] + w[1];
            bcd_write(&mut bytes, val);
        }

        let bytes = bytes.freeze();
        Ok(Serial { bytes })
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_bcd_time() {
//         let time = Utc.ymd(2020, 1, 9).and_hms(23, 23, 0);
//         let bcd_time = Token::bcd_time(&time);

//         assert_eq!(bcd_time, Bytes::from_static(&[32, 32, 1, 9, 35, 32, 0, 0]));
//     }

//     #[test]
//     fn test_key_from_time() {
//         let serial = [3, 5, 6, 2, 6, 9, 9, 9, 1, 4, 4, 9];
//         let time = Utc.ymd(2020, 1, 10).and_hms(0, 4, 0);
//         let bcd_time = bcd_time(time);

//         let mut key0 = [0; 16];
//         key_from_time(bcd_time, 2, &serial, &mut key0);

//         assert_eq!(
//             key0,
//             [32, 32, 170, 170, 170, 170, 170, 170, 105, 153, 20, 73, 187, 187, 187, 187,]
//         );
//     }
// }
