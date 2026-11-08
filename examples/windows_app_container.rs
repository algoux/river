//! Windows AppContainer 沙箱能力演示
//!
//! 本示例完整展示 Windows AppContainer 的核心能力：
//! 1. Profile 管理：创建、打开、删除 AppContainer Profile
//! 2. SID 操作：获取并显示 AppContainer 的 SID
//! 3. ACL 授权：为 AppContainer 授予目录读写/只读权限
//! 4. 沙箱进程启动：使用 PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 启动受限子进程
//! 5. 隔离验证：演示文件系统访问限制和环境变量隔离
//!
//! 运行方式：cargo run --example windows_app_container

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
        SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSID, SECURITY_CAPABILITIES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
        DeleteProcThreadAttributeList, GetExitCodeProcess, WaitForSingleObject,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
        CREATE_UNICODE_ENVIRONMENT, ResumeThread,
    };

    // ======================== userenv API (AppContainer Profile) ========================
    #[allow(clippy::upper_case_acronyms)]
    type HRESULT = i32;
    #[allow(clippy::upper_case_acronyms)]
    type PCWSTR = *const u16;

    const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;
    const HRESULT_PROFILE_NOT_FOUND: i32 = 0x8007_0490u32 as i32;

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn CreateAppContainerProfile(
            appcontainername: PCWSTR,
            displayname: PCWSTR,
            description: PCWSTR,
            capabilitiessid: *const PSID,
            capabilitycount: u32,
            appcontainersid: *mut PSID,
        ) -> HRESULT;
        fn DeriveAppContainerSidFromAppContainerName(
            appcontainername: PCWSTR,
            appcontainersid: *mut PSID,
        ) -> HRESULT;
        fn DeleteAppContainerProfile(appcontainername: PCWSTR) -> HRESULT;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;
    }

    // ======================== 辅助函数 ========================

    /// 将 Rust 字符串转换为以 null 结尾的宽字符串 (UTF-16)
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// 读取 NUL 终止的宽字符串
    unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
        unsafe {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    /// 序列化 Profile 创建（避免并发竞争）
    static PROFILE_CREATE_LOCK: Mutex<()> = Mutex::new(());

    // ======================== AppContainer Profile 管理 ========================

    struct AppContainerProfile {
        sid: PSID,
        name: String,
    }

    impl AppContainerProfile {
        /// 创建或打开一个 AppContainer Profile
        fn create_or_open(name: &str) -> io::Result<Self> {
            let _guard = PROFILE_CREATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

            let wide_name = to_wide(name);
            let mut sid: PSID = ptr::null_mut();

            // 尝试创建 Profile
            let hr = unsafe {
                CreateAppContainerProfile(
                    wide_name.as_ptr(),
                    wide_name.as_ptr(),
                    wide_name.as_ptr(),
                    ptr::null(),
                    0,
                    &mut sid as *mut PSID,
                )
            };

            if hr == 0 && !sid.is_null() {
                println!("  ✅ Profile '{}' 创建成功", name);
                return Ok(AppContainerProfile {
                    sid,
                    name: name.to_string(),
                });
            }

            if hr == HRESULT_ALREADY_EXISTS || sid.is_null() {
                // Profile 已存在，派生 SID
                let mut derived_sid: PSID = ptr::null_mut();
                let derive_hr = unsafe {
                    DeriveAppContainerSidFromAppContainerName(
                        wide_name.as_ptr(),
                        &mut derived_sid as *mut PSID,
                    )
                };
                if derive_hr == 0 && !derived_sid.is_null() {
                    println!("  ✅ Profile '{}' 已存在，SID 派生成功", name);
                    return Ok(AppContainerProfile {
                        sid: derived_sid,
                        name: name.to_string(),
                    });
                }
            }

            Err(io::Error::from_raw_os_error(hr))
        }

        /// 获取 SID 的字符串表示
        fn sid_string(&self) -> io::Result<String> {
            let mut wide: *mut u16 = ptr::null_mut();
            let ok = unsafe { ConvertSidToStringSidW(self.sid as _, &mut wide) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let s = unsafe { wide_ptr_to_string(wide) };
            unsafe { LocalFree(wide as HLOCAL) };
            Ok(s)
        }

        /// 获取原始 SID 指针（用于 ACL 操作）
        fn sid(&self) -> PSID {
            self.sid
        }

        /// 删除 Profile
        fn delete(self) -> io::Result<()> {
            let wide_name = to_wide(&self.name);
            let hr = unsafe { DeleteAppContainerProfile(wide_name.as_ptr()) };
            if hr != 0 && hr != HRESULT_PROFILE_NOT_FOUND {
                return Err(io::Error::from_raw_os_error(hr));
            }
            println!("  ✅ Profile '{}' 已删除", self.name);
            Ok(())
        }
    }

    impl Drop for AppContainerProfile {
        fn drop(&mut self) {
            if !self.sid.is_null() {
                unsafe { LocalFree(self.sid as HLOCAL) };
                self.sid = ptr::null_mut();
            }
        }
    }

    // ======================== ACL 授权 ========================

    const CWD_GRANT_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
    const RO_GRANT_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    const CONTAINER_AND_OBJECT_INHERIT: u32 = 0x3;

    /// 为 AppContainer 授予目录读写权限
    fn grant_rw(path: &Path, sid: PSID) -> io::Result<()> {
        grant(path, sid, CWD_GRANT_RIGHTS)
    }

    /// 为 AppContainer 授予目录只读权限
    fn grant_ro(path: &Path, sid: PSID) -> io::Result<()> {
        grant(path, sid, RO_GRANT_RIGHTS)
    }

    fn grant(path: &Path, sid: PSID, rights: u32) -> io::Result<()> {
        let wide = to_wide(&path.display().to_string());

        // 读取现有 DACL
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = ptr::null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut sd,
            )
        };
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        // 构建新的 ACE
        let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
        unsafe { BuildTrusteeWithSidW(&mut trustee, sid as _) };

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: rights,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: CONTAINER_AND_OBJECT_INHERIT,
            Trustee: trustee,
        };

        let mut new_dacl: *mut ACL = ptr::null_mut();
        let merge_err = unsafe {
            SetEntriesInAclW(1, &entry, dacl, &mut new_dacl)
        };

        let write_err = if merge_err == 0 {
            unsafe {
                SetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    new_dacl,
                    ptr::null(),
                )
            }
        } else {
            merge_err
        };

        unsafe {
            if !new_dacl.is_null() {
                LocalFree(new_dacl as HLOCAL);
            }
            if !sd.is_null() {
                LocalFree(sd as HLOCAL);
            }
        }

        if write_err != 0 {
            return Err(io::Error::from_raw_os_error(write_err as i32));
        }
        Ok(())
    }

    // ======================== 沙箱进程启动 ========================

    /// 构建 UTF-16 环境变量块
    fn build_env_block(vars: &[(String, String)]) -> Vec<u16> {
        let mut sorted = vars.to_vec();
        sorted.sort_unstable_by(|(a, _), (b, _)| {
            a.bytes()
                .map(|c| c.to_ascii_lowercase())
                .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
        });
        let mut block = Vec::new();
        for (k, v) in sorted {
            block.extend(k.encode_utf16());
            block.push('=' as u16);
            block.extend(v.encode_utf16());
            block.push(0);
        }
        block.push(0);
        block
    }

    /// 在 AppContainer 中启动子进程并捕获输出
    fn spawn_in_appcontainer(
        ac: &AppContainerProfile,
        cmd: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env_vars: &[(String, String)],
    ) -> io::Result<(u32, String, String)> {
        // 创建管道捕获输出
        let mut sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
        sa.nLength = size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = 1;
        sa.lpSecurityDescriptor = ptr::null_mut();

        let mut stdout_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut stdout_write: HANDLE = INVALID_HANDLE_VALUE;
        let mut stderr_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut stderr_write: HANDLE = INVALID_HANDLE_VALUE;

        if unsafe { CreatePipe(&mut stdout_read, &mut stdout_write, &sa, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { CreatePipe(&mut stderr_read, &mut stderr_write, &sa, 0) } == 0 {
            unsafe { CloseHandle(stdout_read); CloseHandle(stdout_write) };
            return Err(io::Error::last_os_error());
        }

        // 构建命令行
        let mut cmdline = format!("\"{}\"", cmd);
        for arg in args {
            cmdline.push(' ');
            cmdline.push_str(arg);
        }
        let mut cmdline_wide = to_wide(&cmdline);

        // 构建环境变量块
        let env_block = build_env_block(env_vars);

        // 设置 STARTUPINFOEXW
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdOutput = stdout_write;
        si.StartupInfo.hStdError = stderr_write;
        si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;

        // 准备属性列表
        let handles = [stdout_write, stderr_write];
        let mut sec_caps = SECURITY_CAPABILITIES {
            AppContainerSid: ac.sid(),
            Capabilities: ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };

        // 计算属性列表大小
        let mut attr_size = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut attr_size);
        }
        let mut attr_buf = vec![0u8; attr_size];
        if unsafe {
            InitializeProcThreadAttributeList(attr_buf.as_mut_ptr() as *mut _, 2, 0, &mut attr_size)
        } == 0 {
            unsafe {
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
                CloseHandle(stderr_read);
                CloseHandle(stderr_write);
            }
            return Err(io::Error::last_os_error());
        }

        // 添加 HANDLE_LIST 属性
        if unsafe {
            UpdateProcThreadAttribute(
                attr_buf.as_mut_ptr() as *mut _,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *mut _,
                size_of::<[HANDLE; 2]>(),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0 {
            unsafe {
                DeleteProcThreadAttributeList(attr_buf.as_mut_ptr() as *mut _);
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
                CloseHandle(stderr_read);
                CloseHandle(stderr_write);
            }
            return Err(io::Error::last_os_error());
        }

        // 添加 SECURITY_CAPABILITIES 属性
        if unsafe {
            UpdateProcThreadAttribute(
                attr_buf.as_mut_ptr() as *mut _,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &mut sec_caps as *mut _ as *mut _,
                size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0 {
            unsafe {
                DeleteProcThreadAttributeList(attr_buf.as_mut_ptr() as *mut _);
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
                CloseHandle(stderr_read);
                CloseHandle(stderr_write);
            }
            return Err(io::Error::last_os_error());
        }

        si.lpAttributeList = attr_buf.as_mut_ptr() as *mut _;

        let cwd_wide = cwd.map(|p| to_wide(&p.display().to_string()));

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;

        let ok = unsafe {
            CreateProcessW(
                ptr::null(),
                cmdline_wide.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1, // bInheritHandles
                flags,
                env_block.as_ptr() as *const _,
                cwd_wide.as_ref().map(|w| w.as_ptr()).unwrap_or(ptr::null()),
                &si.StartupInfo as *const STARTUPINFOW as *mut _,
                &mut pi,
            )
        };

        // 清理属性列表
        unsafe { DeleteProcThreadAttributeList(attr_buf.as_mut_ptr() as *mut _) };

        // 关闭父进程的写端
        unsafe {
            CloseHandle(stdout_write);
            CloseHandle(stderr_write);
        }

        if ok == 0 {
            unsafe {
                CloseHandle(stdout_read);
                CloseHandle(stderr_read);
            }
            return Err(io::Error::last_os_error());
        }

        // 恢复进程执行
        unsafe { ResumeThread(pi.hThread) };

        // 等待进程完成
        unsafe { WaitForSingleObject(pi.hProcess, u32::MAX) };

        // 读取输出
        let stdout_data = read_pipe_to_string(stdout_read);
        let stderr_data = read_pipe_to_string(stderr_read);

        // 获取退出码
        let mut exit_code: u32 = 0;
        unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };

        // 清理句柄
        unsafe {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(stdout_read);
            CloseHandle(stderr_read);
        }

        Ok((exit_code, stdout_data, stderr_data))
    }

    fn read_pipe_to_string(pipe: HANDLE) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    pipe,
                    tmp.as_mut_ptr(),
                    tmp.len() as u32,
                    &mut bytes_read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || bytes_read == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..bytes_read as usize]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    // ======================== 演示流程 ========================

    pub fn run() {
        println!("=== Windows AppContainer 沙箱能力演示 ===\n");

        // ========== 1. Profile 管理 ==========
        println!("【1】AppContainer Profile 管理");
        println!("----------------------------------------");

        let profile_name = format!("river.example.{}", std::process::id());
        let ac = match AppContainerProfile::create_or_open(&profile_name) {
            Ok(ac) => ac,
            Err(e) => {
                eprintln!("  ❌ 创建 Profile 失败: {}", e);
                return;
            }
        };

        // 显示 SID
        match ac.sid_string() {
            Ok(sid_str) => println!("  📋 AppContainer SID: {}", sid_str),
            Err(e) => eprintln!("  ❌ 获取 SID 字符串失败: {}", e),
        }
        println!();

        // ========== 2. ACL 授权演示 ==========
        println!("【2】ACL 授权演示");
        println!("----------------------------------------");

        let test_dir = std::env::temp_dir().join(format!("river-ac-test-{}", std::process::id()));
        let ro_dir = std::env::temp_dir().join(format!("river-ac-ro-{}", std::process::id()));

        // 创建测试目录
        if let Err(e) = std::fs::create_dir_all(&test_dir) {
            eprintln!("  ❌ 创建测试目录失败: {}", e);
            return;
        }
        if let Err(e) = std::fs::create_dir_all(&ro_dir) {
            eprintln!("  ❌ 创建只读目录失败: {}", e);
            return;
        }
        println!("  📁 测试目录: {}", test_dir.display());
        println!("  📁 只读目录: {}", ro_dir.display());

        // 授予读写权限
        print!("  🔓 授予读写权限... ");
        match grant_rw(&test_dir, ac.sid()) {
            Ok(_) => println!("✅"),
            Err(e) => {
                println!("❌ ({})", e);
                return;
            }
        }

        // 授予只读权限
        print!("  🔒 授予只读权限... ");
        match grant_ro(&ro_dir, ac.sid()) {
            Ok(_) => println!("✅"),
            Err(e) => {
                println!("❌ ({})", e);
                return;
            }
        }

        // 在只读目录创建一个文件供测试
        let ro_file = ro_dir.join("readonly.txt");
        if let Err(e) = std::fs::write(&ro_file, "This file is read-only for AppContainer") {
            eprintln!("  ❌ 创建只读文件失败: {}", e);
        }
        println!();

        // ========== 3. 沙箱进程启动与隔离验证 ==========
        println!("【3】沙箱进程启动与隔离验证");
        println!("----------------------------------------");

        // 准备环境变量（AppContainer 需要最少的环境变量才能启动 cmd.exe）
        let tmp_subdir = test_dir.join("tmp");
        let _ = std::fs::create_dir_all(&tmp_subdir);

        let env_vars = vec![
            ("SystemRoot".to_string(), std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())),
            ("LOCALAPPDATA".to_string(), std::env::var("LOCALAPPDATA").unwrap_or_default()),
            ("TEMP".to_string(), tmp_subdir.display().to_string()),
            ("TMP".to_string(), tmp_subdir.display().to_string()),
            ("RIVER_SANDBOX_MARKER".to_string(), "sandbox-active".to_string()),
        ];

        let comspec = std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_string());

        // 测试 1: 在授权目录写入文件（应该成功）
        println!("  🧪 测试 1: 在授权目录写入文件");
        match spawn_in_appcontainer(
            &ac,
            &comspec,
            &["/c", "echo Hello from AppContainer > output.txt"],
            Some(&test_dir),
            &env_vars,
        ) {
            Ok((code, _stdout, stderr)) => {
                let output_file = test_dir.join("output.txt");
                if code == 0 && output_file.exists() {
                    let content = std::fs::read_to_string(&output_file).unwrap_or_default();
                    println!("     ✅ 写入成功 (退出码: {})", code);
                    println!("     📄 文件内容: {}", content.trim());
                } else {
                    println!("     ❌ 写入失败 (退出码: {})", code);
                    if !stderr.is_empty() {
                        println!("     stderr: {}", stderr.trim());
                    }
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        // 测试 2: 尝试写入未授权路径（应该失败）
        println!("\n  🧪 测试 2: 尝试写入 C:\\ (应被拒绝)");
        let denied_path = PathBuf::from(r"C:\river-ac-denied-test.txt");
        let _ = std::fs::remove_file(&denied_path);

        match spawn_in_appcontainer(
            &ac,
            &comspec,
            &["/c", "echo x > C:\\river-ac-denied-test.txt"],
            Some(&test_dir),
            &env_vars,
        ) {
            Ok((code, _stdout, stderr)) => {
                if code != 0 && !denied_path.exists() {
                    println!("     ✅ 访问被正确拒绝 (退出码: {})", code);
                } else if denied_path.exists() {
                    println!("     ⚠️  警告: 文件意外被创建！隔离可能失效");
                    let _ = std::fs::remove_file(&denied_path);
                } else {
                    println!("     ℹ️  退出码: {}, stderr: {}", code, stderr.trim());
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        // 测试 3: 环境变量隔离
        println!("\n  🧪 测试 3: 环境变量隔离");
        match spawn_in_appcontainer(
            &ac,
            &comspec,
            &["/c", "echo MARKER=%RIVER_SANDBOX_MARKER% & echo PATH=%PATH%"],
            Some(&test_dir),
            &env_vars,
        ) {
            Ok((code, stdout, _stderr)) => {
                println!("     退出码: {}", code);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        if trimmed.contains("MARKER=sandbox-active") {
                            println!("     ✅ 白名单环境变量可见: {}", trimmed);
                        } else if trimmed.starts_with("PATH=") {
                            if trimmed == "PATH=%PATH%" {
                                println!("     ✅ 宿主 PATH 已隔离 (未泄露)");
                            } else {
                                println!("     ⚠️  PATH 可能泄露: {}", trimmed);
                            }
                        } else {
                            println!("     📤 {}", trimmed);
                        }
                    }
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        // 测试 4: 读取只读目录的文件
        println!("\n  🧪 测试 4: 读取只读目录的文件");
        match spawn_in_appcontainer(
            &ac,
            &comspec,
            &["/c", "type", &ro_file.display().to_string()],
            Some(&test_dir),
            &env_vars,
        ) {
            Ok((code, stdout, stderr)) => {
                if code == 0 {
                    println!("     ✅ 读取成功: {}", stdout.trim());
                } else {
                    println!("     ❌ 读取失败 (退出码: {}): {}", code, stderr.trim());
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        // 测试 5: 尝试修改只读文件（应该失败）
        println!("\n  🧪 测试 5: 尝试修改只读文件 (应被拒绝)");
        match spawn_in_appcontainer(
            &ac,
            &comspec,
            &["/c", "echo modified >>", &ro_file.display().to_string()],
            Some(&test_dir),
            &env_vars,
        ) {
            Ok((code, _stdout, _stderr)) => {
                let content = std::fs::read_to_string(&ro_file).unwrap_or_default();
                if code != 0 || !content.contains("modified") {
                    println!("     ✅ 写入被正确拒绝 (退出码: {})", code);
                } else {
                    println!("     ⚠️  警告: 只读文件被修改！ACL 可能未生效");
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        println!();

        // ========== 4. 清理 ==========
        println!("【4】清理资源");
        println!("----------------------------------------");

        // 删除 Profile
        if let Err(e) = ac.delete() {
            eprintln!("  ❌ 删除 Profile 失败: {}", e);
        }

        // 删除测试目录
        print!("  🗑️  删除测试目录... ");
        match std::fs::remove_dir_all(&test_dir) {
            Ok(_) => println!("✅"),
            Err(e) => println!("⚠️ ({})", e),
        }
        print!("  🗑️  删除只读目录... ");
        match std::fs::remove_dir_all(&ro_dir) {
            Ok(_) => println!("✅"),
            Err(e) => println!("⚠️ ({})", e),
        }

        println!("\n=== 演示完成 ===");
    }
}

fn main() {
    #[cfg(windows)]
    imp::run();

    #[cfg(not(windows))]
    {
        eprintln!("此示例仅在 Windows 上运行。");
        eprintln!("AppContainer 是 Windows 特有的沙箱机制。");
        std::process::exit(1);
    }
}
