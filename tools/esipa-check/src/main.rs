// Decodes ESipa messages with the eIM's own ASN.1 types and checks that
// re-encoding gives the same bytes. Input lines: "to-eim <hex>" | "to-ipa <hex>".
use eim_asn1::sgp32::{EsipaMessageFromEimToIpa, EsipaMessageFromIpaToEim};
use std::io::BufRead;

fn main() {
    let mut bad = 0;
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut it = line.split_whitespace();
        let (Some(dir), Some(h)) = (it.next(), it.next()) else { continue };
        let label = it.collect::<Vec<_>>().join(" ");
        let b = hex::decode(h).expect("hex");
        let r = if dir == "to-eim" {
            eim_asn1::decode::<EsipaMessageFromIpaToEim>(&b)
                .map(|m| (format!("{m:?}"), eim_asn1::encode(&m).unwrap()))
        } else {
            eim_asn1::decode::<EsipaMessageFromEimToIpa>(&b)
                .map(|m| (format!("{m:?}"), eim_asn1::encode(&m).unwrap()))
        };
        match r {
            Ok((dbg, re)) if re == b => println!("OK   {label}: {}", &dbg[..dbg.len().min(200)]),
            Ok((_, re)) => { bad += 1; println!("DIFF {label}: re-encoded {}", hex::encode(re)) }
            Err(e) => { bad += 1; println!("FAIL {label}: {e}") }
        }
    }
    std::process::exit(if bad > 0 { 1 } else { 0 });
}
