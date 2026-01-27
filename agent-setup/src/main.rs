use der::oid::Arc as OidArc;
use der::{Tag, Tagged};
use pkcs8::{LineEnding, ObjectIdentifier, PrivateKeyInfo};
use rand_core::{OsRng, TryRngCore};
use rustls::pki_types::PrivateKeyDer;
use sec1::EcPrivateKey;
use std::{fs, path::Path};
use std::fmt::Write as fmtWrite;
use std::io::Write;

use der::{AnyRef, EncodePem};

use libcrux::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, SigningKeyType};
use libcrux::{add_key, SecretKey};
use rustls::pki_types::pem::PemObject;

#[derive(Debug)]
enum Error {
    EncodingError,
    IOError,
    Pkcs8Error,
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

fn init_agent(args: [String; 3]) -> Result<(), Error> {
    let [_, _, agent_file_path] = args;
    let mut root_key = [0u8; 32];
    
    let path = Path::new(agent_file_path.as_str());
    OsRng.try_fill_bytes(&mut root_key).unwrap();
    fs::create_dir_all(path).map_err(|_| Error::IOError)?;
    fs::write(&path.join("root_file"), &root_key).map_err(|_| Error::IOError)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn import_key(value: PrivateKeyDer<'_>, agent_path: &Path) -> Result<(String, String), Error> {
    match value {
        PrivateKeyDer::Pkcs8(der) => {
            let private_key_info = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der()).map_err(|_| Error::Pkcs8Error)?;
            let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

            match algo_oid_arcs.as_slice() {
                // `id-ecPublicKey' from RFC 3279
                [1, 2, 840, 10045, 2, 1] => {
                    let parameter = private_key_info
                        .algorithm
                        .parameters
                        .ok_or(Error::Pkcs8Error)?;
                    if parameter.tag() != Tag::ObjectIdentifier {
                        return Err(Error::Pkcs8Error);
                    }

                    let parameter_oid = ObjectIdentifier::from_bytes(parameter.value()).unwrap();
                    let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();
                    let key = private_key_info.private_key;
                    let ec_key = EcPrivateKey::try_from(key).map_err(|_| Error::Pkcs8Error)?;
                    let key = ec_key.private_key;
                    
                    let (scheme, signing_key) = match parameter_oid_arcs.as_slice() {
                        [1, 2, 840, 10045, 3, 1, 7] => {
                            let scheme = b"ECDSA_NISTP256_SHA256";
                            let key = EcDsaP256PrivateKey::try_from(key)
                                .map_err(|_| Error::Pkcs8Error)?;
                            let signing_key = SigningKeyType::EcDsaP256(EcDsaP256PrivKey::new(
                                key,
                                DigestAlgorithm::Sha256,
                            ));
                            (scheme, signing_key)
                        }
                        // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                        // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                        _ => return Err(Error::Pkcs8Error),
                    };

                    let (id, pk) = add_key(SecretKey::SigningKey(signing_key));
                    let hex_id = encode_hex(&id);
                    let mut key_path = String::with_capacity(3);
                    write!(&mut key_path, "{:02x}/", id[0]).unwrap();
                    let key_path = agent_path.join(key_path);
                    let mut entry: [u8; 128] = [0; 128];

                    entry[0] = 0x0a; // \n
                    entry[1..=scheme.len()].copy_from_slice(scheme);
                    entry[scheme.len() + 1] = 0x20; // (blank)
                    entry[scheme.len() + 2 .. scheme.len() + 2 + id.len()].copy_from_slice(&id);
                    let entry_len = scheme.len() + id.len() + 2;
                    
                    let mut agent_file = fs::OpenOptions::new().append(true).open(agent_path.join("root_file")).map_err(|_| Error::IOError)?;
                    fs::create_dir_all(&key_path).map_err(|_| Error::IOError)?;
                    fs::write(key_path.join(&hex_id), &key).map_err(|_| Error::IOError)?;
                    agent_file.write(&entry[..entry_len]).map_err(|_| Error::IOError)?;
                    
                    let pk = pk.as_ref();

                    let curve_parameter = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                    let algorithm = pkcs8::AlgorithmIdentifierRef {
                        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                        parameters: Some(AnyRef::from(&curve_parameter)),
                    };
                    
                    // Add point encoding 04
                    dbg!(pk);

                    let sk_info = PrivateKeyInfo {
                        algorithm: algorithm,
                        private_key: &id,
                        public_key: Some(pk),
                    };
                    let enc_sk = sk_info.to_pem(LineEnding::LF).map_err(|_| Error::EncodingError)?;
                    Ok((enc_sk, hex_id))
                }
                _ => Err(Error::Pkcs8Error),
            }
        }
        _ => Err(Error::Pkcs8Error),
    }
}

fn add_key_wrapper(args: [String; 5]) -> Result<(), Error> {
    let [_, _, key_file_path, agent_file_path, id_file_path] = args;
    
    let agent_path = Path::new(agent_file_path.as_str());
    let id_path = Path::new(id_file_path.as_str());
    
    let private_key = PrivateKeyDer::from_pem_file(key_file_path).map_err(|_| Error::IOError)?;
    let (pem_id, hex_id) = import_key(private_key, agent_path)?;
    // Could use write_pkcs8_pem_file
    fs::write(id_path.join(hex_id), &pem_id).map_err(|_| Error::IOError)
}

fn call_resolver(args: Vec<String>) -> Result<(), Error> {
    if args.len() < 2 {
        return Err(Error::WrongArgumentCount);
    }
    
    match args[1].as_str() {
        "init_agent" => init_agent(args.try_into().map_err(|_| Error::WrongArgumentCount)?),
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
