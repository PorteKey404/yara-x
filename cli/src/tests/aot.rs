use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn compile_and_scan_aot() {
    let temp_dir = TempDir::new().unwrap();
    let yar_file = temp_dir.child("test.yar");
    let aot_file = temp_dir.child("test.aot");
    yar_file.write_str("rule aot_rule { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("compile")
        .arg("--aot")
        .arg("-o")
        .arg(aot_file.path())
        .arg(yar_file.path())
        .assert()
        .success();

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("-C")
        .arg("--aot")
        .arg(aot_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "aot_rule src/tests/testdata/dummy.file",
        ));

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("-C")
        .arg(aot_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure();

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--aot")
        .arg(yar_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure();
}
