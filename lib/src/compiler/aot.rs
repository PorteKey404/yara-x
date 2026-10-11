use std::cell::Cell;

#[cfg(all(
    feature = "aot",
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
compile_error!("`aot` requires Linux x86_64");

thread_local! {
    // (adresse, longueur, fd, offset) de l'artefact en cours de chargement
    static LOADING: Cell<Option<(usize, usize, i32, u64)>> = const { Cell::new(None) };
}

pub(crate) fn loading() -> bool {
    LOADING.get().is_some()
}

#[cfg(feature = "aot")]
pub(crate) type AotFile = Option<memmap2::Mmap>;

#[cfg(feature = "aot")]
pub(crate) use imp::configure;

#[cfg(all(test, feature = "aot"))]
mod tests;

#[cfg(feature = "aot")]
mod imp {
    use std::fs::File;
    use std::io::{Error, Read};
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::ptr::NonNull;
    use std::sync::Arc;

    use super::LOADING;
    use crate::compiler::Rules;
    use crate::errors::SerializationError;
    use crate::wasm;

    const MAGIC: &[u8; 8] = b"YARAXAOT";
    const HEADER_LEN: u64 = 16;
    const ALIGN: u64 = 0x10000;

    struct AotCodeMemory;

    impl wasmtime::CustomCodeMemory for AotCodeMemory {
        fn required_alignment(&self) -> usize {
            4096
        }

        fn publish_executable(
            &self,
            ptr: *const u8,
            len: usize,
        ) -> wasmtime::Result<()> {
            let addr = ptr as usize;
            let region = LOADING
                .get()
                .filter(|&(b, n, ..)| b <= addr && addr + len <= b + n);
            let failed = unsafe {
                match region {
                    // Fichier AOT : RX depuis le fichier
                    Some((base, _, fd, offset)) => {
                        libc::mmap(
                            ptr as *mut _,
                            len,
                            libc::PROT_READ | libc::PROT_EXEC,
                            libc::MAP_PRIVATE | libc::MAP_FIXED,
                            fd,
                            (offset + (addr - base) as u64) as libc::off_t,
                        ) == libc::MAP_FAILED
                    }
                    // JIT : comportement par défaut
                    None => {
                        libc::mprotect(
                            ptr as *mut _,
                            len,
                            libc::PROT_READ | libc::PROT_EXEC,
                        ) != 0
                    }
                }
            };
            if failed {
                let e = Error::last_os_error();
                let msg = format!("cannot make code executable: {e}");
                return Err(Error::new(e.kind(), msg).into());
            }
            Ok(())
        }

        fn unpublish_executable(
            &self,
            _ptr: *const u8,
            _len: usize,
        ) -> wasmtime::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn configure(config: &mut wasmtime::Config) {
        config.with_custom_code_memory(Some(Arc::new(AotCodeMemory)));
    }

    impl Rules {
        /// Serializes the rules and their native code as an AOT file.
        pub fn serialize_aot(&self) -> Result<Vec<u8>, SerializationError> {
            let rules = self.serialize()?;
            let mut bytes = MAGIC.to_vec();
            bytes.extend_from_slice(&(rules.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&rules);
            bytes.resize(
                (bytes.len() as u64).next_multiple_of(ALIGN) as usize,
                0,
            );
            bytes.extend_from_slice(
                &self
                    .wasm_mod()
                    .serialize()
                    .map_err(|e| anyhow::anyhow!(e))?,
            );
            Ok(bytes)
        }

        /// Loads an AOT file without compiling anything. The file must be
        /// trusted and must not change while the rules are alive.
        pub fn deserialize_aot_file<P: AsRef<Path>>(
            path: P,
        ) -> Result<Self, SerializationError> {
            let mut file = File::open(path)?;
            let mut header = [0; HEADER_LEN as usize];
            file.read_exact(&mut header)
                .map_err(|_| SerializationError::InvalidFormat)?;
            let len = u64::from_le_bytes(header[8..].try_into().unwrap());
            let offset = HEADER_LEN
                .checked_add(len)
                .and_then(|n| n.checked_next_multiple_of(ALIGN))
                .filter(|o| {
                    &header[..8] == MAGIC
                        && *o < file.metadata().map_or(0, |m| m.len())
                })
                .ok_or(SerializationError::InvalidFormat)?;
            let map = unsafe {
                memmap2::MmapOptions::new()
                    .offset(offset)
                    .map_copy_read_only(&file)?
            };
            let mut bytes = vec![0; len as usize];
            file.read_exact(&mut bytes)?;

            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    LOADING.set(None);
                }
            }
            let _reset = Reset;
            LOADING.set(Some((
                map.as_ptr() as usize,
                map.len(),
                file.as_raw_fd(),
                offset,
            )));
            let mut rules = Rules::deserialize(bytes)?;
            // `map` doit survivre au module : libéré après lui (`_aot_file`)
            let module = unsafe {
                wasmtime::Module::deserialize_raw(
                    wasm::get_engine(),
                    NonNull::from(&map[..]),
                )
            }
            .map_err(|e| anyhow::anyhow!(e))?;
            rules.compiled_wasm_mod = Some(wasm::runtime::Module(module));
            rules._aot_file = Some(map);
            Ok(rules)
        }
    }
}
