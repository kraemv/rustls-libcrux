use der::oid::Arc as OidArc;
use der::{Tag, Tagged};
use pkcs8::{LineEnding, ObjectIdentifier, PrivateKeyInfo};
use rand_core::{OsRng, TryRngCore};
use rustls::pki_types::PrivateKeyDer;

use std::fs;

use der::{AnyRef, EncodePem};

use libcrux::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, SigningKeyType};
use libcrux::{add_key, SecretKey};
use rustls::pki_types::pem::PemObject;

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

    OsRng.try_fill_bytes(&mut root_key).unwrap();
    fs::write(agent_file_path, &root_key).map_err(|_| Error::IOError)
}

pub fn import_key(value: PrivateKeyDer<'_>) -> Result<String, pkcs8::Error> {
    match value {
        PrivateKeyDer::Pkcs8(der) => {
            let private_key_info = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
            let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

            match algo_oid_arcs.as_slice() {
                // `id-ecPublicKey' from RFC 3279
                [1, 2, 840, 10045, 2, 1] => {
                    let parameter = private_key_info
                        .algorithm
                        .parameters
                        .ok_or(pkcs8::Error::KeyMalformed)?;
                    if parameter.tag() != Tag::ObjectIdentifier {
                        return Err(pkcs8::Error::KeyMalformed);
                    }

                    let parameter_oid = ObjectIdentifier::from_bytes(parameter.value()).unwrap();
                    let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                    let scheme = match parameter_oid_arcs.as_slice() {
                        [1, 2, 840, 10045, 3, 1, 7] => EcdsaSignatureScheme::ECDSA_NISTP256_SHA256,
                        // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                        // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                        _ => return Err(pkcs8::Error::KeyMalformed),
                    };

                    let key = private_key_info.private_key;

                    let signing_key = match scheme {
                        EcdsaSignatureScheme::ECDSA_NISTP256_SHA256 => {
                            let key = EcDsaP256PrivateKey::try_from(key)
                                .map_err(|_| pkcs8::Error::KeyMalformed)?;
                            SigningKeyType::EcDsaP256(EcDsaP256PrivKey::new(
                                key,
                                DigestAlgorithm::Sha256,
                            ))
                        }
                    };

                    let (id, pk) = add_key(SecretKey::SigningKey(signing_key));

                    let pk = pk.as_ref();

                    let curve_parameter = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                    let algorithm = pkcs8::AlgorithmIdentifierRef {
                        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                        parameters: Some(AnyRef::from(&curve_parameter)),
                    };

                    let sk_info = PrivateKeyInfo {
                        algorithm: algorithm,
                        private_key: &id,
                        public_key: Some(pk),
                    };
                    let enc_sk = sk_info.to_pem(LineEnding::LF).expect("Key encoding error");
                    Ok(enc_sk)
                }
                _ => Err(pkcs8::Error::KeyMalformed),
            }
        }
        _ => Err(pkcs8::Error::KeyMalformed),
    }
}

#[derive(Debug)]
enum Error {
    EncodingError,
    IOError,
    UnknownCommand,
    WrongArgumentCount,
}

fn add_key_wrapper(args: [String; 4]) -> Result<(), Error> {
    let [_, _, key_file_path, id_file_path] = args;

    let private_key = PrivateKeyDer::from_pem_file(key_file_path).map_err(|_| Error::IOError)?;
    let pem_id = import_key(private_key).map_err(|_| Error::EncodingError)?;
    fs::write(id_file_path, &pem_id).map_err(|_| Error::IOError)
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
