extern crate chrono;
extern crate openssl;

use std::env;
use rsa_securid::code;

fn main() {
    let serial: Vec<_> = env::var("RSA_AUTH_SERIAL")
        .unwrap()
        .chars()
        .map(|c| c.to_digit(10).unwrap() as u8)
        .collect();

    let seed: Vec<u8> = env::var("RSA_AUTH_SEED")
        .unwrap()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();

    println!("{}", code(&serial, &seed));
}

