use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};

#[derive(Serialize, Deserialize, Debug)]
struct Command {
    action: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    entity_id: Option<String>,
    #[serde(default)]
    src_ip: Option<String>,
}

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Ok(cmd) = serde_json::from_str::<Command>(&line) {
            eprintln!("Loader received action: {}", cmd.action);
        }
    }
}
