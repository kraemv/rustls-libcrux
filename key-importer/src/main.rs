use der::oid::Arc as OidArc;
use der::{Tag, Tagged};
use pkcs8::{LineEnding, PrivateKeyInfo, ObjectIdentifier};
use rustls::pki_types::PrivateKeyDer;

use std::fs;

use der::{AnyRef, EncodePem};

use libcrux::signature::{
    DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey,
    SigningKeyType,
};
use libcrux::{add_key, SecretKey};
use rustls::{
    pki_types::{pem::PemObject},
};

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

const ID_EC_PUBLICKEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ECDSA_NISTP256_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

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
                    
                    let algorithm = pkcs8::AlgorithmIdentifierRef{
                        oid: ID_EC_PUBLICKEY,
                        parameters: Some(AnyRef::from(&ECDSA_NISTP256_SHA256)),
                    };
                    
                    let sk_info = PrivateKeyInfo{
                        algorithm, 
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
    WrongArgumentCount(usize),
}

fn main() -> std::io::Result<()>{
    let args: Vec<String> = std::env::args().collect();
    let args: Result<[String; 3], Error> = args
        .try_into()
        .map_err(|args: Vec<_>| Error::WrongArgumentCount(args.len()));
        
    let args = match args {
        Ok (arg) => arg,
        Err(Error::WrongArgumentCount(n)) =>
            {   
                println!("Error: Unexpected number of arguments ({n})");
                std::process::exit(1);
            }
    };

    let [_, key_file_path, id_file_path] = args;
    
    let private_key = PrivateKeyDer::from_pem_file(key_file_path).expect("Failed to load key");
    let pem_id = import_key(private_key).expect("Encoding failed");
    fs::write(id_file_path, &pem_id).expect("Should be able to write to id path");
    Ok(())
}
