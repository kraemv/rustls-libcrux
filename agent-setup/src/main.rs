use base64ct::{Base64, Encoding};
use der::asn1::{BitStringRef, OctetString, SetOfVec, SetOfRef};
use der::oid::Arc as OidArc;
use der::{Any, FixedTag};
use pkcs8::{LineEnding, ObjectIdentifier, PrivateKeyInfo, spki::AlgorithmIdentifier};
use x509_cert::attr::{Attribute};
use rand_core::{OsRng, TryRngCore};
use rustls::pki_types::PrivateKeyDer;
use sec1::{der::Encode, EcPrivateKey};
use std::{fs, path::Path};
use std::fmt::Write as fmtWrite;
use std::io::Write;

use der::EncodePem;

use libcrux::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, SigningKeyType};
use libcrux::{add_key, SecretKey};
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

fn init_agent(args: [String; 3]) -> Result<(), Error> {
    let [_, _, agent_file_path] = args;
    let mut root_key = [0u8; 32];
    let mut enc_root_key = [0u8; 44];
    
    let path = Path::new(agent_file_path.as_str());
    OsRng.try_fill_bytes(&mut root_key).unwrap();
    Base64::encode(&root_key, &mut enc_root_key).map_err(|_| Error::Encoding)?;
    fs::create_dir_all(path).map_err(|_| Error::IO)?;
    fs::write(path.join("root_file"), enc_root_key).map_err(|_| Error::IO)
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


fn import_key(value: PrivateKeyDer<'_>, agent_path: &Path) -> Result<(String, String), Error> {
    match value {
        PrivateKeyDer::Pkcs8(der) => {
            type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitStringRef<'a>, SetOfRef<'a, Attribute>>;

            let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der()).map_err(|_| Error::Pkcs8)?;
            let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

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
                    
                    let (scheme, signing_key) = match parameter_oid_arcs.as_slice() {
                        [1, 2, 840, 10045, 3, 1, 7] => {
                            let scheme = b"ECDSA_NISTP256_SHA256";
                            let signing_key = SigningKeyType::EcDsaP256(EcDsaP256PrivKey::new(
                                EcDsaP256PrivateKey::try_from(key).map_err(|_| Error::Pkcs8)?,
                                DigestAlgorithm::Sha256,
                            ));
                            (scheme, signing_key)
                        }
                        // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                        // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                        _ => return Err(Error::Pkcs8),
                    };

                    let (id, _) = add_key(SecretKey::SigningKey(signing_key)).map_err(|_| Error::Agent)?;

                    let hex_id = encode_hex(&id);

                    let mut key_path = String::with_capacity(3);
                    write!(&mut key_path, "{:02x}/", id[0]).unwrap();
                    let key_path = agent_path.join(key_path);
                    let root_file = agent_path.join("root_file");
                    let key_file = key_path.join(&hex_id);
                    let mut enc_id: [u8; 44] = [0; 44];
                    Base64::encode(&id, &mut enc_id).map_err(|_| Error::Encoding)?;

                    let entry = [b"\n", scheme.as_slice(), b" ", enc_id.as_slice()].concat();
                    
                    let mut agent_file = fs::OpenOptions::new().append(true).open(root_file).map_err(|_| Error::IO)?;

                    fs::create_dir_all(&key_path).map_err(|_| Error::IO)?;
                    fs::write(key_file, key).map_err(|_| Error::IO)?;
                    agent_file.write(&entry).map_err(|_| Error::IO)?;
                    
                    // let pk = [&[4u8], pub_k.as_ref()].concat();
                    // let pk_ref = BitStringRef::from_bytes(pk.as_slice()).map_err(|_| Error::Encoding)?;

                    let algorithm = AlgorithmIdentifier{
                        oid: ID_EC_PUBLICKEY,
                        parameters: Some(Any::from(ECDSA_NISTP256_SHA256)),
                    };
                    
                    let enc_id = Any::new(OctetString::TAG, id.as_ref()).map_err(|_| Error::Encoding)?;
                    let mut values = SetOfVec::new();
                    values.insert(enc_id).map_err(|_| Error::Encoding)?;
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
                        public_key: None,
                        attributes: Some(attrs_ref),
                    };

                    let enc_sk = sk_info.to_pem(LineEnding::LF).map_err(|_| Error::Encoding)?;
                    Ok((enc_sk, hex_id))
                }
                _ => Err(Error::Pkcs8),
            }
        }
        _ => Err(Error::Pkcs8),
    }
}

fn add_key_wrapper(args: [String; 5]) -> Result<(), Error> {
    let [_, _, key_file_path, agent_file_path, id_file_path] = args;
    
    let agent_path = Path::new(agent_file_path.as_str());
    let id_path = Path::new(id_file_path.as_str());
    
    let private_key = PrivateKeyDer::from_pem_file(key_file_path).map_err(|_| Error::IO)?;
    let (pem_id, hex_id) = import_key(private_key, agent_path)?;
    fs::write(id_path.join(hex_id), &pem_id).map_err(|_| Error::IO)
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
