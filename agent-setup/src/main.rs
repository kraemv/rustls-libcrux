use der::asn1::{BitStringRef, OctetString, SetOfVec, SetOfRef};
use der::oid::Arc as OidArc;
use der::{Any, FixedTag};
use libcrux::agent::signatures::EcDsaP256PrivateKey;
use libcrux::algorithms::ecdsa::{self, DigestAlgorithm};
use pkcs8::{LineEnding, ObjectIdentifier, PrivateKeyInfo, spki::AlgorithmIdentifier};
use x509_cert::attr::{Attribute};
use rustls::pki_types::PrivateKeyDer;
use sec1::{der::Encode, EcPrivateKey};
use std::{fs, path::Path};
use std::fmt::Write as fmtWrite;
use std::env;

use der::EncodePem;

use libcrux::agent::agent::Agent;

use rustls::pki_types::pem::PemObject;

#[derive(Debug)]
enum Error {
    Agent,
    Encoding,
    IO,
    Pkcs8,
    UnknownCommand,
    WrongArgumentCount,
}

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

/*
Agent file format:
line 1: Root key
following lines: Scheme + ID

Directory structure:
Top:
Agent file
Subdirectories:
Hash octets of id, finally secret key
*/
fn setup_path() -> Result<String, Error> {
    env::home_dir().ok_or( Error::IO)?
        .join("agent-setup")
        .into_os_string()
        .into_string()
        .map_err(|_| Error::Encoding)
}

fn init_agent() -> Result<(), Error> {
    let agent_path = setup_path()?;
    let agent = Agent::connect_agent(agent_path)
        .map_err(|_| Error::Agent)?;
    agent.init_agent()
        .map_err(|_| Error::Agent)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

const ID_EC_PUBLICKEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ECDSA_NISTP256_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");


fn import_key(value: PrivateKeyDer<'_>) -> Result<(String, String), Error> {
    match value {
        PrivateKeyDer::Pkcs8(der) => {
            type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitStringRef<'a>, SetOfRef<'a, Attribute>>;

            let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der()).map_err(|_| Error::Pkcs8)?;
            let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

            let agent_path = setup_path()?;
            let agent = Agent::connect_agent(agent_path).map_err(|_| Error::Agent)?;

            match algo_oid_arcs.as_slice() {
                // `id-ecPublicKey' from RFC 3279
                [1, 2, 840, 10045, 2, 1] => {
                    let parameter_oid: ObjectIdentifier = private_key_info
                        .algorithm
                        .parameters
                        .ok_or(Error::Pkcs8)?
                        .to_ref()
                        .try_into().map_err(|_| Error::Pkcs8)?;

                    let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                    let key = EcPrivateKey::try_from(private_key_info.private_key.as_bytes())
                        .map_err(|_| Error::Pkcs8)?
                        .private_key;
                    
                    let (id, pk) = match parameter_oid_arcs.as_slice() {
                        [1, 2, 840, 10045, 3, 1, 7] => {
                            let key = ecdsa::p256::PrivateKey::try_from(key).map_err(|_| Error::Pkcs8)?;
                            let alg = DigestAlgorithm::Sha256;
                            agent.ecdsa_p256_add_key(EcDsaP256PrivateKey::new(key, alg)).map_err(|_| Error::Agent)?
                        }
                        // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                        // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                        _ => return Err(Error::Pkcs8),
                    };
                    
                    let key = pk.get_key().0;
                    let pk: Vec<u8> = [[4u8].as_slice(), key.as_slice()].concat();
                    let pk_ref = BitStringRef::from_bytes(pk.as_slice()).map_err(|_| Error::Encoding)?;

                    let algorithm = AlgorithmIdentifier{
                        oid: ID_EC_PUBLICKEY,
                        parameters: Some(Any::from(ECDSA_NISTP256_SHA256)),
                    };
                    
                    let encoded_id = Any::new(OctetString::TAG, id.as_ref()).map_err(|_| Error::Encoding)?;
                    let mut values = SetOfVec::new();
                    values.insert(encoded_id).map_err(|_| Error::Encoding)?;
                    let attr = Attribute{
                        oid: LOCAL_KEY_ID,
                        values,
                    };
                    let mut attrs = SetOfVec::<Attribute>::new();
                    attrs.insert(attr).map_err(|_| Error::Encoding)?;
                    let attrs_ref = SetOfRef::try_from(attrs.as_slice()).map_err(|_| Error::Pkcs8)?;

                    let mut private_key = [0u8; 32];
                    private_key[31] = 1;
                    let private_key = EcPrivateKey{
                        private_key: private_key.as_ref(),
                        parameters: None,
                        public_key: None,
                    };
                    let private_key = private_key.to_der().map_err(|_| Error::Encoding)?;
                    let private_key = OctetString::new(private_key).map_err(|_| Error::Encoding)?;

                    let sk_info: PkInfoType = PrivateKeyInfo {
                        algorithm,
                        private_key,
                        public_key: Some(pk_ref),
                        attributes: Some(attrs_ref),
                    };

                    let encoded_sk = sk_info.to_pem(LineEnding::LF).map_err(|_| Error::Encoding)?;
                    let hex_id = encode_hex(&id);
                    Ok((encoded_sk, hex_id))
                }
                _ => Err(Error::Pkcs8),
            }
        }
        _ => Err(Error::Pkcs8),
    }
}

fn add_key_wrapper(args: [String; 4]) -> Result<(), Error> {
    let [_, _, key_file_path, id_file_path] = args;
    
    let id_path = Path::new(id_file_path.as_str());
    
    let private_key = PrivateKeyDer::from_pem_file(key_file_path).map_err(|_| Error::IO)?;
    let (pem_id, hex_id) = import_key(private_key)?;
    fs::write(id_path.join(hex_id), &pem_id).map_err(|_| Error::IO)
}

fn call_resolver(args: Vec<String>) -> Result<(), Error> {
    if args.len() < 2 {
        return Err(Error::WrongArgumentCount);
    }
    
    match args[1].as_str() {
        "init_agent" => init_agent(),
        "add_key" => add_key_wrapper(args.try_into().map_err(|_| Error::WrongArgumentCount)?),
        &_ => Err(Error::UnknownCommand),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let res = call_resolver(args);
    
    match res {
        Ok(()) => (),
        Err(e) => {
            println!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
}
