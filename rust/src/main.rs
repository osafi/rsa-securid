#[macro_use]
extern crate clap;

use chrono::prelude::*;
use clap::{App, Arg};
use rsa_securid::Token;

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
                .default_value("17369"),
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

    let serial = matches.value_of("serial").unwrap();
    let seed = matches.value_of("seed").unwrap();
    let pin = matches.value_of("pin").unwrap();
    let flags = matches.value_of("flags").unwrap();

    let token = Token::new(
        serial,
        seed,
        pin,
        flags,
    );

    let time = Utc::now().to_rfc3339();
    let code = token.code(&time);
    println!("{}", code);
}
