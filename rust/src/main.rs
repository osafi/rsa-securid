#[macro_use]
extern crate clap;

use chrono::prelude::*;
use clap::{App, Arg};
use regex::Regex;
use rsa_securid::{Serial, Token};

fn main() {
    let matches = App::new("RSA SecurID Authenticate")
        .version(crate_version!())
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .value_name("SEED")
                .help("Device seed")
                .required(true)
                .require_equals(true),
        )
        .arg(
            Arg::with_name("serial")
                .long("serial")
                .value_name("SERIAL")
                .help("RSA token serial number")
                .required(true)
                .require_equals(true),
        )
        .arg(
            Arg::with_name("pin")
                .long("pin")
                .value_name("PIN")
                .help("Token PIN")
                .require_equals(true)
                .default_value("00000000"),
        )
        .arg(
            Arg::with_name("flags")
                .long("flags")
                .value_name("FLAGS")
                .help("Internal flag for token generation algorithm")
                .require_equals(true)
                .default_value("0100001111011001"),
        )
        .arg(
            Arg::with_name("length")
                .long("length")
                .value_name("LENGTH")
                .help("Length of the returned code")
                .require_equals(true)
                .takes_value(true)
                .default_value("8"),
        )
        .get_matches();

    let serial = value_t!(matches, "serial", Serial).unwrap_or_else(|e| e.exit());

    let seed = {
        let value = matches.value_of("seed").unwrap();
        let re = Regex::new(r"^(?:[[:xdigit:]]{2}:){15}[[:xdigit:]]{2}$").unwrap();
        if !re.is_match(&value) {
            panic!("the seed needs to be 16 octets separated by ':'");
        }

        value
            .split(':')
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect()
    };

    let pin = matches.value_of("pin").unwrap().chars().map(|c| c.to_digit(10).unwrap() as u8).collect();

    let tokens = Token { serial, seed, pin };

    let time = Utc::now();
    println!("{}", tokens.code(&time));
}
