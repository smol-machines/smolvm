//! Protect newly created credential storage without invoking a shell or Keychain.
use std::{
    ffi::c_void,
    fs::OpenOptions,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
        },
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, READ_CONTROL, WRITE_DAC,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
const ERROR: &str = "Cannot protect private SSH identity storage.";
struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Only OS-owned, valid SID pointers enter this function; the output is copied
// before releasing the Windows allocation.
unsafe fn sid_string(sid: *mut c_void) -> Result<String, String> {
    let mut text = ptr::null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(ERROR.into());
    }
    let allocation = Allocation(text.cast());
    let mut length = 0;
    while length < 256 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(ERROR.into());
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| ERROR.to_owned());
    drop(allocation);
    result
}
fn user_sid() -> Result<String, String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(ERROR.into());
    }
    let token = Token(token);
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut size);
    }
    if size == 0 || size > 64 * 1024 {
        return Err(ERROR.into());
    }
    // TOKEN_USER requires pointer alignment; a byte vector does not guarantee it.
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(ERROR.into());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    unsafe { sid_string(user.User.Sid) }
}

pub(super) fn make_private(path: &Path) -> Result<(), String> {
    // Bind validation and ACL changes to the same object, even if another
    // process renames the path. Opening reparse points avoids following links.
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ERROR.to_owned())?;
    let handle = file.as_raw_handle();
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            && information.nNumberOfLinks != 1)
    {
        return Err(
            "Private SSH storage must not use reparse points or additional file links.".into(),
        );
    }
    let user = user_sid()?;
    let mut owner = ptr::null_mut();
    let mut existing = ptr::null_mut();
    if unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut existing,
        )
    } != 0
    {
        return Err(ERROR.into());
    }
    let existing = Allocation(existing);
    let owner = unsafe { sid_string(owner)? };
    // Elevated installers can create files with Administrators or SYSTEM as owner;
    // both already have administrative access, unlike an unrelated user account.
    if owner != user && owner != "S-1-5-32-544" && owner != "S-1-5-18" {
        return Err("Private credential storage belongs to another user.".into());
    }
    drop(existing);
    let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(ERROR.into());
    }
    let descriptor = Allocation(descriptor);
    let mut acl = ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err(ERROR.into());
    }
    if unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    } != 0
    {
        return Err(ERROR.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, fs};
    use windows_sys::Win32::{
        Security::{GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, SE_DACL_PROTECTED},
        Storage::FileSystem::FILE_ALL_ACCESS,
    };

    fn assert_private(path: &Path, protected: bool) {
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        let mut descriptor = ptr::null_mut();
        let mut acl = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut acl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        let descriptor = Allocation(descriptor);
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert_eq!(control & SE_DACL_PROTECTED != 0, protected);
        assert!(!acl.is_null());
        assert_eq!(unsafe { (*acl).AceCount }, 2);
        let mut trustees = BTreeSet::new();
        for index in 0..2 {
            let mut ace = ptr::null_mut();
            assert_ne!(unsafe { GetAce(acl, index, &mut ace) }, 0);
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            assert_eq!(ace.Header.AceType, 0); // ACCESS_ALLOWED_ACE_TYPE
            assert_eq!(ace.Mask, FILE_ALL_ACCESS);
            trustees.insert(unsafe {
                sid_string(ptr::addr_of!(ace.SidStart).cast_mut().cast()).unwrap()
            });
        }
        assert_eq!(
            trustees,
            BTreeSet::from([user_sid().unwrap(), "S-1-5-18".into()])
        );
    }

    #[test]
    fn private_storage_limits_access_and_inheritance_with_an_open_stage() {
        let root = tempfile::tempdir().unwrap();
        make_private(root.path()).unwrap();
        assert_private(root.path(), true);
        let stage = tempfile::NamedTempFile::new_in(root.path()).unwrap();
        assert_private(stage.path(), false);
        make_private(stage.path()).unwrap();
        assert_private(stage.path(), true);
        let alias = root.path().join("linked");
        fs::hard_link(stage.path(), &alias).unwrap();
        assert!(make_private(&alias).is_err());
        assert_private(stage.path(), true);
    }
}
