mod pccs;
mod constants;

use dcap_rs::types::quotes::CertDataType;
use dcap_rs::utils::cert::extract_sgx_extension;
use pccs::{get_certificate_by_id, get_enclave_identity, get_tcbinfo, IPCSDao};
use constants::TDX_TEE_TYPE;

use dcap_rs::types::collaterals::IntelCollateral;
use dcap_rs::types::quotes::version_4::QuoteV4;

#[no_mangle]
pub extern "C" fn verify_quote_dcapv4(quote_ptr: *const u8, quote_ptr_len: usize, out_buf_ptr: *mut u8, out_buf_len: *mut usize) {
    // convert quote_bytes to slice and parse into QuoteV4
    let quote_slice = unsafe { std::slice::from_raw_parts(quote_ptr, quote_ptr_len) };

    let quote_version = u16::from_le_bytes([quote_slice[0], quote_slice[1]]);
    let tee_type = u32::from_le_bytes([quote_slice[4], quote_slice[5], quote_slice[6], quote_slice[7]]);
    
    log::info!("Quote version: {}", quote_version);
    log::info!("TEE Type: {}", tee_type);
    
    // zl: we just want to handle tdx quote for now
    if quote_version != 4 {
        panic!("Unsupported quote version");
    }
    
    if tee_type != TDX_TEE_TYPE {
        panic!("Unsupported tee type");
    }

    let dcap_quote = QuoteV4::from_bytes(quote_slice);

    // get certificates...
    // get root ca and root ca crl
    let (root_ca, root_ca_crl) = get_certificate_by_id(IPCSDao::CA::ROOT).unwrap();
    // get signing ca
    let (signing_ca, _signing_crl) = get_certificate_by_id(IPCSDao::CA::SIGNING).unwrap();
    // get platform ca
    let (_platform_ca, platform_crl) = get_certificate_by_id(IPCSDao::CA::PLATFORM).unwrap();
    // get processor ca
    let (_processor_ca, processor_crl) = get_certificate_by_id(IPCSDao::CA::PROCESSOR).unwrap();
    
    // get fmspc
    let fmspc = get_fmspc_quotev4(&dcap_quote);
    let fmspc_str = hex::encode(fmspc);

    // get tcbinfo, 1 for tdx, 3 for tcbinfov3
    let tcbinfo = get_tcbinfo(1, &fmspc_str, 3).unwrap();

    // get qeidentity
    let qeidentity = get_enclave_identity(pccs::EnclaveIdType::TDQE, 4).unwrap();

    // generate IntelCollateral
    let mut collaterals = IntelCollateral::new();
    collaterals.set_tcbinfo_bytes(&tcbinfo);
    collaterals.set_qeidentity_bytes(&qeidentity);
    collaterals.set_intel_root_ca_der(&root_ca);
    collaterals.set_sgx_tcb_signing_der(&signing_ca);
    collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl);
    collaterals.set_sgx_platform_crl_der(&platform_crl);
    collaterals.set_sgx_processor_crl_der(&processor_crl);

    // get the current time
    let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // verify the quote
    let verified_output = dcap_rs::utils::quotes::version_4::verify_quote_dcapv4(&dcap_quote, &collaterals, current_time);
    let verified_output_bytes = verified_output.to_bytes();
    // ensure that buffer is large enough
    unsafe { assert!(verified_output_bytes.len() <= *out_buf_len); }
    // copy the verified output to the output buffer
    unsafe { out_buf_ptr.copy_from(verified_output_bytes.as_ptr(), verified_output_bytes.len()); }
    // set the length of the output buffer
    unsafe { *out_buf_len = verified_output_bytes.len(); }
}

// TODO: implement this function in dcap-rs
fn get_fmspc_quotev4(quote: &QuoteV4) -> [u8; 6] {
    // zl: quotev4 qe_cert_data is a CertDataType::QeReportCertData
    let fmspc = match quote.signature.qe_cert_data.get_cert_data() {
        CertDataType::QeReportCertData(qe_report_cert_data) => {
            // zl: inner cert_data is a CertDataType::CertChain
            match &qe_report_cert_data.qe_cert_data.get_cert_data() {
                CertDataType::CertChain(cert_chain) => {
                    let pck_cert= &cert_chain.get_certs()[0];
                    let sgx_extensions = extract_sgx_extension(pck_cert);
                    sgx_extensions.fmspc
                },
                _ => panic!("Unexpected CertDataType in QeReportCertData"),
            }
        },
        _ => panic!("Unsupported CertDataType in QeCertData"),
    };
    fmspc
}

#[test]
fn test_verifyv4() {
    // let current_time = chrono::Utc::now().timestamp() as u64;
    use dcap_rs::types::collaterals::IntelCollateral;
    use dcap_rs::types::quotes::version_4::QuoteV4;
    use dcap_rs::utils::quotes::version_4::verify_quote_dcapv4;
    use dcap_rs::utils::cert::{hash_crl_keccak256, hash_x509_keccak256};

    const PINNED_TIME: u64 = 1725950994;

    let mut collaterals = IntelCollateral::new();
    collaterals.set_tcbinfo_bytes(include_bytes!("../data/tcbinfov3_00806f050000.json"));
    collaterals.set_qeidentity_bytes(include_bytes!("../data/qeidentityv2_apiv4.json"));
    collaterals.set_intel_root_ca_der(include_bytes!("../data/Intel_SGX_Provisioning_Certification_RootCA.cer"));
    collaterals.set_sgx_tcb_signing_pem(include_bytes!("../data/signing_cert.pem"));
    collaterals.set_sgx_intel_root_ca_crl_der(include_bytes!("../data/intel_root_ca_crl.der"));
    collaterals.set_sgx_platform_crl_der(include_bytes!("../data/pck_platform_crl.der"));
    collaterals.set_sgx_processor_crl_der(include_bytes!("../data/pck_processor_crl.der"));


    let dcap_quote = QuoteV4::from_bytes(include_bytes!("../data/quote_tdx_00806f050000.dat"));

    let verified_output = verify_quote_dcapv4(&dcap_quote, &collaterals, PINNED_TIME);

    println!("{:?}", verified_output);
    let root_hash = hash_x509_keccak256(&collaterals.get_sgx_intel_root_ca());
    let sign_hash = hash_x509_keccak256(&collaterals.get_sgx_tcb_signing());
    let crl_hash = hash_crl_keccak256(&collaterals.get_sgx_intel_root_ca_crl().unwrap());
    println!("{:?}", root_hash);
    println!("{:?}", sign_hash);
    println!("{:?}", crl_hash);
}

#[test]
fn test_get_certificate_by_id() {
    use pccs::get_certificate_by_id;
    use pccs::IPCSDao;

    let cert = get_certificate_by_id(IPCSDao::CA::ROOT).unwrap();
    println!("{:?}", cert);
}

#[test]
fn test_get_tcbinfo() {
    use std::str;

    let dcap_quote = QuoteV4::from_bytes(include_bytes!("../data/quote_tdx_00806f050000.dat"));
    let fmspc = get_fmspc_quotev4(&dcap_quote);
    let fmspc_str = hex::encode(fmspc);

    let tcbinfo = get_tcbinfo(1, &fmspc_str, 3).unwrap();
    println!("{}", str::from_utf8(&tcbinfo).unwrap());
}

#[test]
fn test_verifyv4_ffi() {
    let dcap_quote_bytes = include_bytes!("../data/quote_tdx_00806f050000.dat");
    // convert slice to raw ptr
    let quote_ptr = dcap_quote_bytes.as_ptr();
    let quote_ptr_len = dcap_quote_bytes.len();

    let mut output_buffer = [0u8; 4096];
    let mut output_buffer_len = output_buffer.len();

    verify_quote_dcapv4(quote_ptr, quote_ptr_len, output_buffer.as_mut_ptr(), &mut output_buffer_len);

    // we'll convert the output buffer into a slice and parse it into a VerifiedOutput
    let simulated_output_buffer = unsafe { std::slice::from_raw_parts(output_buffer.as_ptr(), output_buffer_len) };
    let verified_output = dcap_rs::types::VerifiedOutput::from_bytes(simulated_output_buffer);
    println!("{:?}", verified_output);
}