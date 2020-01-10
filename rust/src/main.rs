#![feature(test)]

extern crate chrono;
extern crate openssl;
extern crate test;

use std::env;
use rsa_securid::code;

fn main() {
    let serial = env::var("RSA_AUTH_SERIAL").unwrap();
    let seed: Vec<u8> = env::var("RSA_AUTH_SEED")
        .unwrap()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();

    println!("{}", code(&serial, &seed));
}

