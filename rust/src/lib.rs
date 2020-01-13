use bytes::{BufMut, Bytes, BytesMut};
use chrono::prelude::*;
use openssl::symm::{encrypt, Cipher};
use regex::Regex;
use std::convert::TryInto;

const FLD_DIGIT_SHIFT: u8 = 6;
const FLD_DIGIT_MASK: u16 = (0b111 << FLD_DIGIT_SHIFT);
const FLD_NUMSECONDS_SHIFT: u16 = 0;
const FLD_NUMSECONDS_MASK: u16 = (0b11 << FLD_NUMSECONDS_SHIFT);

pub fn bcd(val: u8) -> u8 {
    let mut out = val % 10;
    out |= (val / 10 % 10) << 4;
    out
}

pub struct Token {
    serial: Vec<u8>,
    seed: Vec<u8>,
    pin: Vec<u8>,
    flags: u16,
}

impl Token {
    pub fn new(serial: &str, seed: &str, pin: &str, flags: &str) -> Self {
        let serial: Vec<_> = {
            let re = Regex::new(r"^\d{12}$").unwrap();
            if !re.is_match(&serial) {
                panic!("the serial needs to be 12 digits");
            }

            let digits: Vec<_> = serial
                .chars()
                .map(|c| c.to_digit(10).unwrap() as u8)
                .collect();
            digits.chunks(2).map(|c| bcd(10 * c[0] + c[1])).collect()
        };

        let seed = {
            let re = Regex::new(r"^(?:[[:xdigit:]]{2}:){15}[[:xdigit:]]{2}$").unwrap();
            if !re.is_match(&seed) {
                panic!("the seed needs to be 16 octets separated by ':'");
            }

            seed.split(':')
                .map(|x| u8::from_str_radix(x, 16).unwrap())
                .collect()
        };

        let pin = pin.chars().map(|c| c.to_digit(10).unwrap() as u8).collect();
        let flags = flags.parse().unwrap();

        Token {
            serial,
            seed,
            pin,
            flags,
        }
    }

    pub fn code(&self, time: &DateTime<Utc>) -> String {
        let bcd_time = self.bcd_time(&time);

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

        let i = match self.interval() {
            Interval::ThirtySeconds => {
                // translated without testing, so this might be wrong...
                let mut i = 0;
                if time.minute() % 2 == 1 {
                    i |= 0b1000;
                }
                if time.minute() >= 30 {
                    i |= 0b0100;
                }
                i
            }
            Interval::OneMinute => ((time.minute() as usize) & 0b11) << 2,
        };

        let raw: Vec<_> = u32::from_be_bytes(key0[i..i + 4].try_into().unwrap())
            .to_string()
            .chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();

        let len = ((self.flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) as usize;
        let skip = raw.len() - len - 1;
        raw
            .iter()
            .skip(skip) // truncate
            .enumerate()
            .map(|(i, x)| x + self.pin.get(i).unwrap_or(&0))
            .map(|x| x.to_string())
            .collect()
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
                0..=7 => {
                    if i < bcd_time_slice.len() {
                        bcd_time_slice[i]
                    } else {
                        0xaa
                    }
                }
                8..=11 => self.serial[i - 6],
                12..=15 => 0xbb,
                _ => key[i],
            }
        }

        return bytes.freeze();
    }

    fn bcd_time(&self, time: &DateTime<Utc>) -> Bytes {
        let mut bytes = BytesMut::with_capacity(8);

        bytes.put_slice(&[
            bcd((time.year() % 100) as u8),
            bcd((time.year() / 100 % 100) as u8),
            bcd(time.month() as u8),
            bcd(time.day() as u8),
            bcd(time.hour() as u8),
            bcd((time.minute() & self.minute_mask()) as u8),
            0,
            0,
        ]);

        bytes.freeze()
    }

    fn interval(&self) -> Interval {
        if (self.flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT == 0 {
            Interval::ThirtySeconds
        } else {
            Interval::OneMinute
        }
    }

    fn minute_mask(&self) -> u32 {
        match self.interval() {
            Interval::ThirtySeconds => !0b01,
            Interval::OneMinute => !0b11,
        }
    }
}

#[derive(Debug)]
enum Interval {
    ThirtySeconds,
    OneMinute,
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
