//! Conformance binary: reads JCS vectors and emits canonical + digest.
//!
//! Usage:
//!   racs-v02-conformance --vector <jcs-vector-file>
//!       prints JSON {got_canonical, got_digest, expected_canonical, expected_digest, match}
//!       exits 0 if match else 1.
//!   racs-v02-conformance --file <json-file>
//!       prints JSON {canonical, digest}.
//!   racs-v02-conformance --model-digest <golden-file>
//!       parses the GovernanceEvaluation payload from a golden vector file and
//!       prints JSON {digest} (used by the cross-language gate, stage 3B).

use std::env;
use std::fs;
use std::process;

use racs_v02::{canonical_string, sha256_digest, GovernanceEvaluation};
use serde_json::Value;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str());
    let path = args.get(2).map(|s| s.as_str());

    match (mode, path) {
        (Some("--vector"), Some(p)) => {
            let text = fs::read_to_string(p).unwrap_or_else(|e| die(&format!("read {p}: {e}")));
            let vec: Value = serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("parse {p}: {e}")));
            // support both official JCS vectors (input/expected_*) and RACS
            // payload vectors (payload/canonical_payload/payload_digest)
            let (subject, exp_canon, exp_digest) = if vec.get("input").is_some() {
                (vec["input"].clone(), vec["expected_canonical"].clone(), vec["expected_digest"].clone())
            } else if vec.get("payload").is_some() {
                (vec["payload"].clone(), vec["canonical_payload"].clone(), vec["payload_digest"].clone())
            } else {
                die("vector has neither 'input' nor 'payload'");
            };
            let got_canon = canonical_string(&subject).unwrap();
            let got_digest = sha256_digest(&subject).unwrap();
            let exp_canon = exp_canon.as_str().unwrap_or("");
            let exp_digest = exp_digest.as_str().unwrap_or("");
            let ok = got_canon == exp_canon && got_digest == exp_digest;
            let out = serde_json::json!({
                "got_canonical": got_canon,
                "got_digest": got_digest,
                "expected_canonical": exp_canon,
                "expected_digest": exp_digest,
                "match": ok,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            if !ok { process::exit(1); }
        }
        (Some("--file"), Some(p)) => {
            let text = fs::read_to_string(p).unwrap_or_else(|e| die(&format!("read {p}: {e}")));
            let val: Value =
                serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("parse {p}: {e}")));
            let canon = canonical_string(&val).unwrap();
            let digest = sha256_digest(&val).unwrap();
            println!(
                "{}",
                serde_json::json!({"canonical": canon, "digest": digest})
            );
        }
        (Some("--model-digest"), Some(p)) => {
            let text = fs::read_to_string(p).unwrap_or_else(|e| die(&format!("read {p}: {e}")));
            let vec: Value =
                serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("parse {p}: {e}")));
            let payload = vec
                .get("payload")
                .cloned()
                .unwrap_or_else(|| die("golden has no 'payload'"));
            let ev: GovernanceEvaluation =
                serde_json::from_value(payload).unwrap_or_else(|e| die(&format!("model: {e}")));
            let digest = ev.digest().unwrap();
            println!("{}", serde_json::json!({"digest": digest}));
        }
        _ => {
            die("usage: racs-v02-conformance (--vector <file> | --file <file> | --model-digest <golden-file>)");
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(2);
}
