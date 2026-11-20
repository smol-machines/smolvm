//! Native credential reads: persisted references never trigger authorization UI.
use super::{ResolutionFailure, Zeroizing};
type Result = std::result::Result<Zeroizing<Vec<u8>>, ResolutionFailure>;

#[cfg(target_os = "linux")]
pub(super) fn read(service: &str, account: Option<&str>, allow_ui: bool) -> Result {
    use secret_service::{blocking::SecretService, EncryptionType, Error};
    fn failure(error: Error) -> ResolutionFailure {
        match error {
            Error::Locked | Error::Prompt | Error::PromptDisconnected => {
                ResolutionFailure::KeychainInteractionRequired
            }
            Error::NoResult => ResolutionFailure::KeychainItemMissing,
            _ => ResolutionFailure::KeychainUnavailable,
        }
    }
    let connection = SecretService::connect(EncryptionType::Dh).map_err(failure)?;
    let mut attributes = std::collections::HashMap::from([("service", service)]);
    if let Some(account) = account {
        attributes.insert("account", account);
    }
    let items = connection.search_items(attributes).map_err(failure)?;
    let item = if let Some(item) = items.unlocked.into_iter().next() {
        item
    } else if let Some(item) = items.locked.into_iter().next() {
        if !allow_ui {
            return Err(ResolutionFailure::KeychainInteractionRequired);
        }
        item.unlock().map_err(failure)?;
        item
    } else {
        return Err(ResolutionFailure::KeychainItemMissing);
    };
    // GetSecret itself never calls Unlock/Prompt, including a lock racing search.
    item.get_secret().map(Zeroizing::new).map_err(failure)
}

#[cfg(target_os = "macos")]
pub(super) use macos::read;

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use core_foundation::{
        array::CFArray,
        base::{CFType, TCFType},
        boolean::CFBoolean,
        data::CFData,
        dictionary::CFDictionary,
        string::{CFString, CFStringRef},
    };
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework_sys::{
        base::{
            errSecAuthFailed as AUTH_FAILED, errSecItemNotFound as ITEM_NOT_FOUND,
            errSecSuccess as SUCCESS,
        },
        item::*,
        keychain_item::SecItemCopyMatching,
    };
    unsafe extern "C" {
        static kSecUseAuthenticationUIFail: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;
    }
    fn pair(key: CFStringRef, value: impl TCFType) -> (CFString, CFType) {
        // Security.framework keys are static; each wrapper retains its value.
        (
            unsafe { CFString::wrap_under_get_rule(key) },
            value.as_CFType(),
        )
    }
    pub(crate) fn read(service: &str, account: Option<&str>, allow_ui: bool) -> Result {
        read_from(service, account, allow_ui, None)
    }
    fn read_from(
        service: &str,
        account: Option<&str>,
        allow_ui: bool,
        keychain: Option<&SecKeychain>,
    ) -> Result {
        let mut query = unsafe {
            vec![
                pair(
                    kSecClass,
                    CFString::wrap_under_get_rule(kSecClassGenericPassword),
                ),
                pair(kSecAttrService, CFString::new(service)),
                pair(kSecReturnData, CFBoolean::true_value()),
                pair(
                    kSecMatchLimit,
                    CFString::wrap_under_get_rule(kSecMatchLimitOne),
                ),
            ]
        };
        unsafe {
            if let Some(account) = account {
                query.push(pair(kSecAttrAccount, CFString::new(account)));
            }
            if let Some(keychain) = keychain {
                query.push(pair(
                    kSecMatchSearchList,
                    CFArray::from_CFTypes(std::slice::from_ref(keychain)),
                ));
            }
            if !allow_ui {
                query.push(pair(
                    kSecUseAuthenticationUI,
                    CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail),
                ));
            }
        }
        let query = CFDictionary::from_CFType_pairs(&query);
        let mut result = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        let result = (!result.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(result) });
        match status {
            SUCCESS => {
                let data = result
                    .and_then(|v| v.downcast::<CFData>())
                    .ok_or(ResolutionFailure::KeychainUnavailable)?;
                if data.len() as u64 > super::super::MAX_FROM_FILE_BYTES {
                    return Err(ResolutionFailure::KeychainUnavailable);
                }
                Ok(Zeroizing::new(data.bytes().to_vec()))
            }
            ITEM_NOT_FOUND => Err(ResolutionFailure::KeychainItemMissing),
            // errSecInteractionNotAllowed and userCanceledErr are not exposed
            // by the sys crate. Neither is a missing credential.
            -25308 | -128 | AUTH_FAILED => Err(ResolutionFailure::KeychainInteractionRequired),
            _ => Err(ResolutionFailure::KeychainUnavailable),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use security_framework::os::macos::keychain::CreateOptions;
        unsafe extern "C" {
            fn SecKeychainDelete(keychain: <SecKeychain as TCFType>::Ref) -> i32;
            fn SecKeychainLock(keychain: <SecKeychain as TCFType>::Ref) -> i32;
        }
        #[test]
        #[ignore = "uses only a disposable native Keychain; requires macOS login session"]
        fn replay_does_not_unlock_or_authorize_keychain_items() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("owned.keychain");
            let password = "owned-credential-fixture";
            let keychain = CreateOptions::new()
                .password(password)
                .create(&path)
                .unwrap();
            struct Cleanup(SecKeychain);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    unsafe {
                        SecKeychainDelete(self.0.as_concrete_TypeRef());
                    }
                }
            }
            let mut cleanup = Cleanup(keychain);
            let keychain = &mut cleanup.0;
            let service = "smolvm-owned-secret-replay";
            keychain
                .set_generic_password(service, "allowed", b"fixture-value")
                .unwrap();
            for allow_ui in [false, true] {
                assert_eq!(
                    read_from(service, Some("allowed"), allow_ui, Some(keychain))
                        .unwrap()
                        .as_slice(),
                    b"fixture-value"
                );
            }
            assert_eq!(
                read_from(service, Some("absent"), false, Some(keychain)).unwrap_err(),
                ResolutionFailure::KeychainItemMissing
            );
            assert_eq!(
                unsafe { SecKeychainLock(keychain.as_concrete_TypeRef()) },
                0
            );
            assert_eq!(
                read_from(service, Some("allowed"), false, Some(keychain)).unwrap_err(),
                ResolutionFailure::KeychainInteractionRequired
            );
            keychain.unlock(Some(password)).unwrap();
            assert_eq!(
                read_from(service, Some("allowed"), false, Some(keychain))
                    .unwrap()
                    .as_slice(),
                b"fixture-value"
            );
            let output = std::process::Command::new("/usr/bin/security")
                .args([
                    "add-generic-password",
                    "-s",
                    service,
                    "-a",
                    "unapproved",
                    "-w",
                    "fixture-value",
                    "-T",
                    "/usr/bin/false",
                ])
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(
                read_from(service, Some("unapproved"), false, Some(keychain)).unwrap_err(),
                ResolutionFailure::KeychainInteractionRequired
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use secret_service::{blocking::SecretService, EncryptionType};

    #[test]
    #[ignore = "requires an explicitly isolated Secret Service and session bus"]
    fn replay_does_not_unlock_private_secret_service() {
        assert_eq!(
            std::env::var("SMOLVM_TEST_PRIVATE_SECRET_SERVICE").as_deref(),
            Ok("1")
        );
        let connection = SecretService::connect(EncryptionType::Dh).unwrap();
        let collection = connection.get_default_collection().unwrap();
        assert!(!collection.is_locked().unwrap());
        let service = format!("smolvm-owned-replay-{}", std::process::id());
        let attributes =
            std::collections::HashMap::from([("service", service.as_str()), ("account", "owned")]);
        let item = collection
            .create_item(
                "owned fixture",
                attributes,
                b"fixture-value",
                true,
                "text/plain",
            )
            .unwrap();
        let reference = crate::secrets::keychain_ref(format!("{service}/owned"));
        let resolve = || {
            crate::secrets::resolve_secret_ref_classified(
                "TEST",
                &reference,
                crate::secrets::ResolutionScope::RecordReplay,
            )
        };
        assert_eq!(resolve().unwrap().as_str(), "fixture-value");
        assert_eq!(
            read(&service, Some("absent"), false).unwrap_err(),
            ResolutionFailure::KeychainItemMissing
        );
        item.lock().unwrap();
        assert_eq!(
            resolve().unwrap_err(),
            ResolutionFailure::KeychainInteractionRequired
        );
        assert!(item.is_locked().unwrap());
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn read(_: &str, _: Option<&str>, _: bool) -> Result {
    Err(ResolutionFailure::KeychainUnavailable)
}
