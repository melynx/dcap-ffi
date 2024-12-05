
use std::{future::IntoFuture, error::Error};

use crate::constants::{DEFAULT_RPC_URL, PCS_DAO_ADDRESS, FMSPC_TCB_DAO_ADDRESS, ENCLAVE_ID_DAO_ADDRESS};

use alloy::{
    sol,
    providers::ProviderBuilder,
    primitives::{Address, U256},
};

#[derive(Debug)]
#[allow(dead_code)]
pub enum EnclaveIdType {
    QE,
    QVE,
    TDQE,
}

sol! {
    #[sol(rpc)]
    interface IPCSDao {
        #[derive(Debug)]
        enum CA {
            ROOT,
            PROCESSOR,
            PLATFORM,
            SIGNING
        }

        #[derive(Debug)]
        function getCertificateById(CA ca) external view returns (bytes memory cert, bytes memory crl);
    }

    #[sol(rpc)]
    interface IFmspcTcbDao {
        #[derive(Debug)]
        struct TcbInfoJsonObj {
            string tcbInfoStr;
            bytes signature;
        }

        #[derive(Debug)]
        function getTcbInfo(uint256 tcbType, string calldata fmspc, uint256 version) returns (TcbInfoJsonObj memory tcbObj);
    }

    #[sol(rpc)]
    interface IEnclaveIdentityDao {
        #[derive(Debug)]
        struct EnclaveIdentityJsonObj {
            string identityStr;
            bytes signature;
        }

        #[derive(Debug)]
        function getEnclaveIdentity(uint256 id, uint256 version) returns (EnclaveIdentityJsonObj memory enclaveIdObj);
    }
}

pub fn get_certificate_by_id(ca_id: IPCSDao::CA) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let rpc_url = DEFAULT_RPC_URL.parse().expect("Failed to parse RPC URL");
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let pcs_dao_address = hex::decode(PCS_DAO_ADDRESS).expect("invalid address hex");
    let pcs_dao_contract = IPCSDao::new(Address::from_slice(&pcs_dao_address), &provider);

    let call_builder = pcs_dao_contract.getCertificateById(ca_id);

    let call_return = rt.block_on(call_builder.call().into_future())?;

    let cert = call_return.cert.to_vec();
    let crl = call_return.crl.to_vec();

    Ok((cert, crl))
}

pub fn get_tcbinfo(tcb_type: u8, fmspc: &str, version: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let rpc_url = DEFAULT_RPC_URL.parse().expect("Failed to parse RPC URL");
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let fmspc_tcb_dao_address_slice =
        hex::decode(FMSPC_TCB_DAO_ADDRESS).expect("Invalid address hex");
    let fmspc_tcb_dao_contract =
        IFmspcTcbDao::new(Address::from_slice(&fmspc_tcb_dao_address_slice), &provider);

    let call_builder = fmspc_tcb_dao_contract.getTcbInfo(
        U256::from(tcb_type),
        String::from(fmspc),
        U256::from(version),
    );

    let call_return = rt.block_on(call_builder.call().into_future())?;
    let tcb_info_str = call_return.tcbObj.tcbInfoStr;
    let signature_bytes = call_return.tcbObj.signature;

    if tcb_info_str.len() == 0 || signature_bytes.len() == 0 {
        return Err(format!(
            "TCBInfo for FMSPC: {}; Version: {} is missing and must be upserted to on-chain pccs",
            fmspc, version
        ).into());
    }

    let signature = signature_bytes.to_string();

    let ret_str = format!(
        "{{\"tcbInfo\": {}, \"signature\": \"{}\"}}",
        tcb_info_str,
        signature.as_str().trim_start_matches("0x")
    );

    let ret = ret_str.into_bytes();
    Ok(ret)
}

pub fn get_enclave_identity(id: EnclaveIdType, version: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let rpc_url = DEFAULT_RPC_URL.parse().expect("Failed to parse RPC URL");
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let enclave_id_dao_address_slice =
        hex::decode(ENCLAVE_ID_DAO_ADDRESS).expect("Invalid address hex");

    let enclave_id_dao_contract = IEnclaveIdentityDao::new(
        Address::from_slice(&enclave_id_dao_address_slice),
        &provider,
    );

    let enclave_id_type_uint256;
    match id {
        EnclaveIdType::QE => enclave_id_type_uint256 = U256::from(0),
        EnclaveIdType::QVE => enclave_id_type_uint256 = U256::from(1),
        EnclaveIdType::TDQE => enclave_id_type_uint256 = U256::from(2),
    }

    let call_builder =
        enclave_id_dao_contract.getEnclaveIdentity(enclave_id_type_uint256, U256::from(version));

    let call_return = rt.block_on(call_builder.call().into_future())?;

    let identity_str = call_return.enclaveIdObj.identityStr;
    let signature_bytes = call_return.enclaveIdObj.signature;

    if identity_str.len() == 0 || signature_bytes.len() == 0 {
        return Err(format!(
            "QEIdentity for ID: {:?}; Version: {} is missing and must be upserted to on-chain pccs",
            id, version
        ).into());
    }

    let signature = signature_bytes.to_string();

    let ret_str = format!(
        "{{\"enclaveIdentity\": {}, \"signature\": \"{}\"}}",
        identity_str,
        signature.as_str().trim_start_matches("0x")
    );

    let ret = ret_str.into_bytes();
    Ok(ret)
}