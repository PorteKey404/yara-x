use std::fs::File;
use std::path::Path;

use clap::{Arg, ArgMatches, arg};
use yara_x::Rules;

pub fn compile_arg() -> Option<Arg> {
    cfg!(feature = "aot")
        .then(|| arg!(--"aot").help("Write an AOT file (rules + native code)"))
}

pub fn scan_arg() -> Option<Arg> {
    cfg!(feature = "aot").then(|| {
        arg!(--"aot")
            .help("RULES_PATH is an AOT file")
            .requires("compiled-rules")
    })
}

pub fn serialize(
    rules: &Rules,
    args: &ArgMatches,
    output: &File,
) -> anyhow::Result<()> {
    #[cfg(feature = "aot")]
    if args.get_flag("aot") {
        use std::io::Write;
        let mut output = output;
        output.write_all(&rules.serialize_aot()?)?;
        return Ok(());
    }
    let _ = args;
    Ok(rules.serialize_into(output)?)
}

pub fn deserialize(
    args: &ArgMatches,
    path: &Path,
    file: File,
) -> anyhow::Result<Rules> {
    #[cfg(feature = "aot")]
    if args.get_flag("aot") {
        return Ok(Rules::deserialize_aot_file(path)?);
    }
    let _ = (args, path);
    Ok(Rules::deserialize_from(file)?)
}
