pub(crate) mod utils {
    use windows::core::{PCSTR, PSTR};

    pub unsafe fn string_to_pcstr(string: &mut String) -> PCSTR {
        string.push('\0');
        PCSTR(string.as_ptr())
    }

    pub unsafe fn string_to_pstr(string: &mut String) -> PSTR {
        string.push('\0');
        PSTR(string.as_mut_ptr())
    }
}
