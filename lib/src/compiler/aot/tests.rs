use crate::compiler::Rules;
use crate::errors::SerializationError;
use crate::{Scanner, compile};
use std::fs;

#[test]
fn aot_file() {
    let rules =
        compile(r#"rule test { strings: $a = "foo" condition: $a }"#).unwrap();
    let dir = std::env::temp_dir()
        .join(format!("yara-x-aot-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rules.aot");
    fs::write(&path, rules.serialize_aot().unwrap()).unwrap();

    let aot_rules = Rules::deserialize_aot_file(&path).unwrap();
    let mut scanner = Scanner::new(&aot_rules);
    assert_eq!(scanner.scan(b"xxfooxx").unwrap().matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"bar").unwrap().matching_rules().len(), 0);

    for (name, bytes) in [
        ("rules.yarc", rules.serialize().unwrap()),
        ("bad.aot", [&b"YARAXAOT"[..], &[0xff; 8]].concat()),
        ("short.aot", [&b"YARAXAOT"[..], &[0; 8]].concat()),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        assert!(matches!(
            Rules::deserialize_aot_file(dir.join(name)).err().unwrap(),
            SerializationError::InvalidFormat
        ));
    }
    drop(scanner);
    drop(aot_rules);
    fs::remove_dir_all(&dir).unwrap();
}
