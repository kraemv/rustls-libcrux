use crate::Provider;
use crate::sign::TLSSigningKey;

use std::vec::Vec;
use std::sync::Arc;
use std::fmt::Debug;

use der::Any;
use der::oid::Arc as OidArc;
use der::asn1::{BitString, OctetString, SetOfRef};
use libcrux::agent::signatures::{EcDsaP256PublicKey, Ed25519PublicKey, SHA256};
use libcrux::libcrux::signature::{EcDsaP256, Ed25519, SigningKey, SigningKeyID};
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::PrivateKeyDer;
use x509_cert::attr::Attribute;

impl<T> TLSSigningKey<T> 
where 
    T: SigningKey + Clone + Debug + 'static,
{
    fn load_key(der: PrivatePkcs8KeyDer<'_>) -> Result<Arc<dyn rustls::sign::SigningKey>, pkcs8::Error> {
        let sk = T::try_from(der).map_err(|_| pkcs8::Error::KeyMalformed)?;
        Ok(Arc::new(Self::new(sk)))
    }
}

fn to_rustls_error(err: pkcs8::Error) -> rustls::Error {
    rustls::Error::General(alloc::format!("{}", err))
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let key = match key_der {
            PrivateKeyDer::Pkcs8(der) => {
                type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;

                let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der()).map_err(to_rustls_error)?;
                let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

                match algo_oid_arcs.as_slice() {
                    // `id-ecPublicKey' from RFC 3279
                    [1, 2, 840, 10045, 2, 1] => {
                        let parameter_oid: ObjectIdentifier = private_key_info
                            .algorithm
                            .parameters
                            .ok_or(to_rustls_error(pkcs8::Error::KeyMalformed))?
                            .to_ref()
                            .try_into().map_err(|_| to_rustls_error(pkcs8::Error::KeyMalformed))?;

                        let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                        // Check it is an EcDsaP256 key
                        (parameter_oid_arcs.as_slice() == [1, 2, 840, 10045, 3, 1, 7]).then_some(()).ok_or(pkcs8::Error::KeyMalformed).map_err(to_rustls_error)?;
                        
                        TLSSigningKey::<SigningKeyID::<EcDsaP256, EcDsaP256PublicKey::<SHA256>>>::load_key(der)
                    }
                    [1, 3, 101, 112] => {
                        TLSSigningKey::<SigningKeyID::<Ed25519, Ed25519PublicKey>>::load_key(der)
                    }
                    _ => Err(pkcs8::Error::KeyMalformed),
                }
            }
            _ => Err(pkcs8::Error::KeyMalformed)
        };

        key.map_err(to_rustls_error)

    }
}