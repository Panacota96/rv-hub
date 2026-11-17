//! The only `unsafe` code of RV Hub: the Win32 calls of the Authenticode check.
//!
//! Why `unsafe` is needed and allowed here (and nowhere else; the crate is `#![deny(unsafe_code)]`):
//! WinVerifyTrust and the WinTrust helpers are C functions that take and return raw pointers to C structures.
//! The `windows` crate exposes them as `unsafe fn`. This module keeps every pointer local to [`verify_file`]:
//! the path buffer outlives both WinVerifyTrust calls, the provider data is only read between the VERIFY and
//! the CLOSE call (which frees it), every pointer is checked for null before it is read, and only owned data
//! (the HRESULT and a copy of the root certificate's bytes) leaves the function. The decision itself
//! (`classify`) is safe Rust, tested on every platform.
//!
//! When WinVerifyTrust cannot build the chain (CERT_E_CHAINING: the Rakvor root is neither installed in Windows
//! nor embedded in the signature; `signtool /ac` leaves a self-signed root out), the signer's chain is built again
//! with a chain engine whose only trusted root is the pinned one (`hExclusiveRoot`): same leaf, same signing time,
//! code-signing usage required. A chain that ends there, without errors, is reported as one that ends at the
//! pinned root; anything else keeps the original CERT_E_CHAINING.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_ENGINE_CONFIG,
    CERT_CHAIN_PARA, CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_ALWAYS,
    CERT_STORE_PROV_MEMORY, CERT_TRUST_NO_ERROR, CERT_USAGE_MATCH, CTL_USAGE,
    CertAddCertificateContextToStore, CertCloseStore, CertCreateCertificateChainEngine,
    CertCreateCertificateContext, CertFreeCertificateChain, CertFreeCertificateChainEngine,
    CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore, HCERTCHAINENGINE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, szOID_PKIX_KP_CODE_SIGNING,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::PCWSTR;

/// CERT_E_CHAINING: WinVerifyTrust could not build the signer's chain to any root it knows.
const CERT_E_CHAINING: i32 = 0x800B_010A_u32 as i32;
/// CERT_E_UNTRUSTEDROOT: the chain was built but its root is not in the Windows trust store.
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B_0109_u32 as i32;

/// Runs WinVerifyTrust on `path` (no UI, no revocation check, no network retrieval) and returns its HRESULT and
/// the DER bytes of the root certificate of the signer's chain, when the provider built one. On CERT_E_CHAINING
/// the chain is built again against `pinned_root_der` alone (see the module documentation): when that succeeds the
/// answer is CERT_E_UNTRUSTEDROOT with the pinned root, exactly as on a machine where the root is installed but not
/// trusted by Windows.
pub(super) fn verify_file(path: &Path, pinned_root_der: &[u8]) -> (i32, Option<Vec<u8>>) {
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
    let mut root = unsafe { root_certificate(&data) };
    let mut hresult = hresult;
    if hresult == CERT_E_CHAINING {
        // SAFETY: as above, the provider data is valid until CLOSE; the rebuilt chain is freed inside.
        if unsafe { chains_to_pinned_root(&data, pinned_root_der) } {
            hresult = CERT_E_UNTRUSTEDROOT;
            root = Some(pinned_root_der.to_vec());
        }
    }
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

/// Builds the first signer's chain again with `pinned_root_der` as the only trusted root, at the time the
/// provider verified the signature (its timestamp, else now), for code signing, without revocation checks and
/// without network retrieval (cache only).
/// True only when the chain has no error and ends at exactly that certificate.
unsafe fn chains_to_pinned_root(data: &WINTRUST_DATA, pinned_root_der: &[u8]) -> bool {
    unsafe {
        if data.hWVTStateData.0.is_null() || pinned_root_der.is_empty() {
            return false;
        }
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return false;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return false;
        }
        let sgnr = &*sgnr;
        let leaf: *const CERT_CONTEXT = (*sgnr.pasCertChain).pCert;
        if leaf.is_null() {
            return false;
        }
        let root =
            CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pinned_root_der);
        if root.is_null() {
            return false;
        }
        let mut ok = false;
        if let Ok(store) = CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            Default::default(),
            None,
            CERT_OPEN_STORE_FLAGS(0),
            None,
        ) {
            if CertAddCertificateContextToStore(Some(store), root, CERT_STORE_ADD_ALWAYS, None)
                .is_ok()
            {
                let config = CERT_CHAIN_ENGINE_CONFIG {
                    cbSize: std::mem::size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32,
                    hExclusiveRoot: store,
                    ..Default::default()
                };
                let mut engine = HCERTCHAINENGINE::default();
                if CertCreateCertificateChainEngine(&config, &mut engine).is_ok() {
                    let mut usage = [windows::core::PSTR(szOID_PKIX_KP_CODE_SIGNING.0 as *mut u8)];
                    let para = CERT_CHAIN_PARA {
                        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
                        RequestedUsage: CERT_USAGE_MATCH {
                            dwType: 0, // USAGE_MATCH_TYPE_AND
                            Usage: CTL_USAGE {
                                cUsageIdentifier: 1,
                                rgpszUsageIdentifier: usage.as_mut_ptr(),
                            },
                        },
                        ..Default::default()
                    };
                    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
                    let built = CertGetCertificateChain(
                        Some(engine),
                        leaf,
                        Some(&sgnr.sftVerifyAsOf),
                        Some((*leaf).hCertStore),
                        &para,
                        // Offline, like WinVerifyTrust above (WTD_CACHE_ONLY_URL_RETRIEVAL): no AIA download.
                        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                        None,
                        &mut chain,
                    );
                    if built.is_ok() && !chain.is_null() {
                        ok = (*chain).TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR
                            && last_element_is(chain, pinned_root_der);
                        CertFreeCertificateChain(chain);
                    }
                    CertFreeCertificateChainEngine(Some(engine));
                }
            }
            let _ = CertCloseStore(Some(store), 0);
        }
        let _ = CertFreeCertificateContext(Some(root));
        ok
    }
}

/// True when the last element of the first simple chain is exactly `der`.
unsafe fn last_element_is(chain: *const CERT_CHAIN_CONTEXT, der: &[u8]) -> bool {
    unsafe {
        if (*chain).cChain == 0 || (*chain).rgpChain.is_null() {
            return false;
        }
        let simple = *(*chain).rgpChain;
        if simple.is_null() || (*simple).cElement == 0 || (*simple).rgpElement.is_null() {
            return false;
        }
        let last = *(*simple).rgpElement.add((*simple).cElement as usize - 1);
        if last.is_null() || (*last).pCertContext.is_null() {
            return false;
        }
        let c = &*(*last).pCertContext;
        !c.pbCertEncoded.is_null()
            && std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize) == der
    }
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
