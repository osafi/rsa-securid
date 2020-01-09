extern crate chrono;

use chrono::prelude::*;

struct Token {
    length: usize,
    seed: String,
    serial: String,
}

fn main() {
    let time = Utc::now();

    let bcd_time = bcd_time(time);

    dbg!(bcd_time);

    println!("Hello, world!");
}

fn bcd_write(out: &mut [u32], mut val: u32) {
    for v in out {
        *v = bcd_offset(&mut val);
    }
}

fn bcd_offset(val: &mut u32) -> u32 {
    let mut out = *val % 10;
    *val /= 10;
    out |= (*val % 10) << 4;
    *val /= 10;

    out
}

fn bcd_time(time: DateTime<Utc>) -> [u32; 8] {
    let mut bcd_time = [0; 8];

    bcd_write(&mut bcd_time[0..=1], time.year() as u32);
    bcd_write(&mut bcd_time[2..3], time.month());
    bcd_write(&mut bcd_time[3..4], time.day());
    bcd_write(&mut bcd_time[4..5], time.hour());
    bcd_write(&mut bcd_time[5..6], time.minute() & !0b11);

    bcd_time
}

#[test]
fn test_bcd_time() {
    let time = Utc.ymd(2020, 1, 9).and_hms(23, 23, 0);
    let bcd_time = bcd_time(time);

    assert_eq!(bcd_time, [32, 32, 1, 9, 35, 32, 0, 0]);
}


    // private static int[] key_from_time(int[] bcd_time, int bcd_time_bytes, String serial, int[] key) {
    //     Arrays.fill(key, 0, 8, 0xaa);
    //     Arrays.fill(key, 12, key.length, 0xbb);
    //     System.arraycopy(bcd_time, 0, key, 0, bcd_time_bytes);

    //     int k = 8;
    //     for (int i = 4; i < 12; i += 2) {
    //         key[k++] = ((serial.charAt(i) - '0') << 4) | (serial.charAt(i + 1) - '0');
    //     }

    //     return key;
    // }
