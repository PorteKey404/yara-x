use std::ffi::{CString, c_void};
use std::fs;

use crate::{
    YRX_RESULT, YRX_RULE, yrx_buffer_destroy, yrx_compile, yrx_rules_destroy,
    yrx_rules_serialize, yrx_scanner_create, yrx_scanner_destroy,
    yrx_scanner_on_matching_rule, yrx_scanner_scan,
};

use super::{yrx_rules_deserialize_aot_file, yrx_rules_serialize_aot};

extern "C" fn count(_rule: *const YRX_RULE, user_data: *mut c_void) {
    unsafe { *(user_data as *mut i32) += 1 };
}

#[test]
fn capi_aot_file() {
    let dir = std::env::temp_dir()
        .join(format!("yara-x-capi-aot-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let (aot, yarc) = (dir.join("rules.aot"), dir.join("rules.yarc"));
    let c = |p: &std::path::Path| CString::new(p.to_str().unwrap()).unwrap();

    unsafe {
        let mut rules = std::ptr::null_mut();
        let src = c"rule test { strings: $a = \"foo\" condition: $a }";
        assert_eq!(
            yrx_compile(src.as_ptr(), &mut rules),
            YRX_RESULT::YRX_SUCCESS
        );

        let mut buf = std::ptr::null_mut();
        assert_eq!(
            yrx_rules_serialize_aot(rules, &mut buf),
            YRX_RESULT::YRX_SUCCESS
        );
        fs::write(
            &aot,
            std::slice::from_raw_parts((*buf).data, (*buf).length),
        )
        .unwrap();
        yrx_buffer_destroy(buf);
        yrx_rules_serialize(rules, &mut buf);
        fs::write(
            &yarc,
            std::slice::from_raw_parts((*buf).data, (*buf).length),
        )
        .unwrap();
        yrx_buffer_destroy(buf);
        yrx_rules_destroy(rules);

        let mut aot_rules = std::ptr::null_mut();
        assert_eq!(
            yrx_rules_deserialize_aot_file(c(&aot).as_ptr(), &mut aot_rules),
            YRX_RESULT::YRX_SUCCESS
        );
        let mut scanner = std::ptr::null_mut();
        let mut matches = 0;
        yrx_scanner_create(aot_rules, &mut scanner);
        yrx_scanner_on_matching_rule(
            scanner,
            Some(count),
            &mut matches as *mut i32 as *mut c_void,
        );
        yrx_scanner_scan(scanner, b"xxfooxx".as_ptr(), 7);
        assert_eq!(matches, 1);
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(aot_rules);

        assert_eq!(
            yrx_rules_deserialize_aot_file(c(&yarc).as_ptr(), &mut aot_rules),
            YRX_RESULT::YRX_SERIALIZATION_ERROR
        );
        assert_eq!(
            yrx_rules_deserialize_aot_file(std::ptr::null(), &mut aot_rules),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}
