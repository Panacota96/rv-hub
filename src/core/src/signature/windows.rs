//! The only `unsafe` code of RV Hub: the Win32 calls of the Authenticode check.
//!
//! Why `unsafe` is needed and allowed here (and nowhere else; the crate is `#![deny(unsafe_code)]`):
//! WinVerifyTrust and the WinTrust helpers are C functions that take and return raw pointers to C structures.
//! The `windows` crate exposes them as `unsafe fn`. This module keeps every pointer local to [`verify_file`]:
//! the path buffer outlives both WinVerifyTrust calls, the provider data is only read between the VERIFY and
//! the CLOSE call (which frees it), every pointer is checked for null before it is read, and only owned data
//! (the HRESULT and a copy of the root certificate's bytes) leaves the function. The decision itself
//! (`classify`) is safe Rust, tested on every platform.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::PCWSTR;

/// Runs WinVerifyTrust on `path` (no UI, no revocation check, no network retrieval) and returns its HRESULT and
/// the DER bytes of the root certificate of the signer's chain, when the provider built one.
pub(super) fn verify_file(path: &Path) -> (i32, Option<Vec<u8>>) {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file as *mut WINTRUST_FILE_INFO,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file` are valid, initialised structures that live until the CLOSE call below;
    // `wide` (the NUL-terminated path) outlives both calls.
    let hresult = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    // SAFETY: the provider data belongs to the state handle and is valid until WTD_STATEACTION_CLOSE; every
    // pointer is checked for null and the certificate bytes are copied before the state is closed.
    let root = unsafe { root_certificate(&data) };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same structures as above; CLOSE releases the state allocated by VERIFY.
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        );
    }
    (hresult, root)
}

/// Root certificate (DER) of the first signer's chain: the chain context built by the provider
/// (CertGetCertificateChain), else the provider's certificate list.
unsafe fn root_certificate(data: &WINTRUST_DATA) -> Option<Vec<u8>> {
    unsafe {
        if data.hWVTStateData.0.is_null() {
            return None;
        }
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return None;
        }
        let sgnr = &*sgnr;
        let mut cert = std::ptr::null();
        let chain = sgnr.pChainContext;
        if !chain.is_null() && (*chain).cChain > 0 && !(*chain).rgpChain.is_null() {
            let simple = *(*chain).rgpChain;
            if !simple.is_null() && (*simple).cElement > 0 && !(*simple).rgpElement.is_null() {
                let last = *(*simple).rgpElement.add((*simple).cElement as usize - 1);
                if !last.is_null() {
                    cert = (*last).pCertContext;
                }
            }
        }
        if cert.is_null() && sgnr.csCertChain > 0 && !sgnr.pasCertChain.is_null() {
            cert = (*sgnr.pasCertChain.add(sgnr.csCertChain as usize - 1)).pCert;
        }
        if cert.is_null() {
            return None;
        }
        let c = &*cert;
        if c.pbCertEncoded.is_null() || c.cbCertEncoded == 0 {
            return None;
        }
        Some(std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec())
    }
}
