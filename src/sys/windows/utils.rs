pub(crate) mod utils {
    use crate::error::Error::WinError;
    use crate::error::Result;
    use std::mem::size_of;
    use std::ptr;
    use windows::core::{PCSTR, PSTR};
    use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE, TRUE};
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{CreateFileA, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};

    pub unsafe fn string_to_pcstr(string: &mut String) -> PCSTR {
        string.push('\0');
        PCSTR(string.as_ptr())
    }

    pub unsafe fn string_to_pstr(string: &mut String) -> PSTR {
        string.push('\0');
        PSTR(string.as_mut_ptr())
    }

    pub unsafe fn handle_from_file(string: &String) -> Result<HANDLE> {
        let mut string = string.clone();

        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: TRUE,  // 指明这个 handle 需要被子进程继承
        };

        return match CreateFileA(
            string_to_pcstr(&mut string),
            GENERIC_WRITE.0,
            Default::default(),
            Some(&sa),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(h_file) => {
                Ok(h_file)
            }
            Err(e) => {
                Err(WinError(String::from(file!()), line!(), e))
            }
        }
    }
}
