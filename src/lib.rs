//! Implement PQC-Kyber with X25519 to shared a secret key in a post-quantum resistant way.
//! The test implements a way to implement the communication between Alice and bob.
//! Be careful though, verification of public key is not performed here.
//! <div class="warning">This crate has not undergo any security audit and should be used with caution!</div>
//!
//! ```rust
//! use std::sync::mpsc::channel;
//! use std::time::Duration;
//! use std::thread;
//! use pqx::*;
//! let (sender1, receiver1) = channel();
//! let (sender2, receiver2) = channel();
//! let thread = thread::spawn(move || {
//!     let bob_s = Combinedkey::default();
//!     let bob_p = Combinedpub::new(&bob_s);
//!     sender1.send(bob_p.to_string()).unwrap();
//!     let cipher = receiver2.recv_timeout(Duration::new(20,0)).unwrap();
//!     let cipher = Combinedcipher::from(cipher);
//!     Combinedshared::new(bob_s, cipher).unwrap()
//! });
//! let alice_s = Combinedkey::default();
//! let pubkey = receiver1.recv_timeout(Duration::new(20,0)).unwrap();
//! let pubkey = Combinedpub::try_from(pubkey.as_str()).unwrap();
//! let kyberelem = Combinedcipher::new(&alice_s,&pubkey).unwrap();
//! sender2.send(kyberelem.getcipher()).unwrap();
//! let shared = Combinedshared::getfromshared(kyberelem, pubkey, alice_s).unwrap().getshared(SHAREDSIZE::Med);
//! let result = thread.join().unwrap().getshared(SHAREDSIZE::Med);
//! assert!(shared==result,"Invalid shared, got {:#?} and {:#?}",shared,result);
//! //println!("Valid shared, got {}",hex::encode(shared.get()))
//! ```
#[cfg(feature = "keystore")]
pub mod key;
use rand::{self, thread_rng};
use safe_pqc_kyber::*;
use sha2::*;
use std::fmt::Display;
use x25519_dalek::*;
use zeroize::{Zeroize, ZeroizeOnDrop};
/// PqxError gathers every error that can happen on this crate. There are opaque by design and distinguishs bad input or error in generation.
#[derive(Debug, Clone, Copy)]
pub enum PqxError {
    KyberError,
    InvalidInput,
}
/// Generation of the shared key
#[derive(Clone, Debug, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Combinedshared {
    shared: Box<[u8; Combinedshared::SHAREDLEN]>,
}
/// Final shared key after rounds of sha256
#[derive(Clone, Debug, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Finalkey {
    shared: Vec<u8>,
}
/// The combinated key containing private key for X25519 and Kyber, should not be transferred
pub struct Combinedkey {
    kyber: safe_pqc_kyber::Keypair,
    x25519: EphemeralSecret,
}
/// The combination key containing public key for X25519 and Kyber.
#[derive(Clone, Debug, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Combinedpub {
    pub kyber: [u8; KYBER_PUBLICKEYBYTES],
    pub x25519: x25519_dalek::PublicKey,
}
/// The combinated shared to share between persons to obtain the secret key as well as the shared_key on server side
#[derive(Clone, Debug, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Combinedcipher {
    pub cipher: [u8; Combinedcipher::KEYSIZE],
    shared_secret: Option<[u8; KYBER_SSBYTES]>,
}
impl Default for Combinedkey {
    /// Create a random-secure key for both algorithms
    fn default() -> Self {
        let mut rng = thread_rng();
        let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
        let kyber = safe_pqc_kyber::keypair(&mut rng);
        Combinedkey {
            kyber,
            x25519: alice_secret,
        }
    }
}
#[cfg(feature = "keystore")]
impl TryFrom<[u8; KYBER_PUBLICKEYBYTES + KYBER_SECRETKEYBYTES]> for Combinedkey {
    type Error = PqxError;
    //Extraction from public key then secret key
    fn try_from(
        data: [u8; KYBER_PUBLICKEYBYTES + KYBER_SECRETKEYBYTES],
    ) -> Result<Self, Self::Error> {
        let (public, secret) = (
            data[..KYBER_PUBLICKEYBYTES].try_into(),
            data[KYBER_PUBLICKEYBYTES..].try_into(),
        );
        let (public, secret) = match (public, secret) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return Err(PqxError::InvalidInput),
        };
        let mut public: [u8; KYBER_PUBLICKEYBYTES] = public;
        let mut secret: [u8; KYBER_SECRETKEYBYTES] = secret;
        let mut rng = rand::thread_rng();
        //Try to encapsulate and decapsule to verify secret key matches public key
        let (ciphertext, shared_secret) = match encapsulate(&public, &mut rng) {
            Ok(a) => a,
            _ => return Err(PqxError::InvalidInput),
        };
        let expected_shared_secret = match decapsulate(&ciphertext, &secret) {
            Ok(a) => a,
            _ => return Err(PqxError::InvalidInput),
        };
        //If it does match, return a KeyPair
        if expected_shared_secret == shared_secret {
            let key = Keypair { public, secret };
            public.zeroize();
            secret.zeroize();
            let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
            Ok(Combinedkey {
                kyber: key,
                x25519: alice_secret,
            })
        } else {
            //Else return an error
            Err(PqxError::InvalidInput)
        }
    }
}
impl Combinedkey {
    /// Create a random-secure key for both algorithms
    pub fn new() -> Self {
        Self::default()
    }
    /// Display public or private key
    #[cfg(feature = "keystore")]
    pub fn displaykyberkey(&self, private: bool) -> &[u8] {
        match private {
            false => &self.kyber.public,
            true => &self.kyber.secret
        }
    }
    /// Check kyber keys comparaison
    pub fn checkkeys(&self, other: &Self) -> bool {
        self.kyber == other.kyber
    }
    /// Display public or private key
    #[cfg(feature = "keystore")]
    pub fn getkyberkeypair(&self) -> &Keypair {
        &self.kyber
    }
}
impl Finalkey {
    /// Get the final key to be used for others algorithms (such as AES-GCM...)
    pub fn get(&self) -> &[u8] {
        &self.shared
    }
}
/// Display the key in an hexadecimal format `a0a0a0a0`
#[cfg(feature = "to_string")]
impl Display for Finalkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.shared))
    }
}
impl Combinedpub {
    const KEYSIZE: usize = x25519_dalek::X25519_BASEPOINT_BYTES.as_slice().len();
    /// Create public keys from private keys
    pub fn new(key: &Combinedkey) -> Self {
        let kyber = key.kyber.public;
        let x25519 = x25519_dalek::PublicKey::from(&key.x25519);
        Combinedpub { kyber, x25519 }
    }
}
/// Give public key as string to be sent to network
#[cfg(feature = "to_string")]
impl Display for Combinedpub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}|{}",
            hex::encode(self.kyber),
            hex::encode(self.x25519.as_bytes())
        )
    }
}
/// Create public key from info transmitted from network
#[cfg(feature = "to_string")]
impl TryFrom<&str> for Combinedpub {
    type Error = PqxError;

    fn try_from(info: &str) -> Result<Self, Self::Error> {
        let (kyber, x25519) = match info.split_once('|') {
            None => return Err(PqxError::InvalidInput),
            Some(a) => a,
        };
        let (kyber, x25519) = match (hex::decode(kyber), hex::decode(x25519)) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return Err(PqxError::InvalidInput),
        };
        if kyber.len() != KYBER_PUBLICKEYBYTES {
            return Err(PqxError::InvalidInput);
        }
        let kyber = match kyber[..KYBER_PUBLICKEYBYTES].try_into() {
            Ok(s) => s,
            _ => return Err(PqxError::InvalidInput),
        };
        if x25519.len() != Self::KEYSIZE {
            return Err(PqxError::InvalidInput);
        }
        let x25519: [u8; Self::KEYSIZE] = match x25519[..Self::KEYSIZE].try_into() {
            Ok(s) => s,
            _ => return Err(PqxError::InvalidInput),
        };
        let x25519 = x25519_dalek::PublicKey::from(x25519);
        Ok(Combinedpub { kyber, x25519 })
    }
}
impl Combinedcipher {
    /// Length of the cipher
    const KEYSIZE: usize = KYBER_CIPHERTEXTBYTES + X25519_BASEPOINT_BYTES.as_slice().len();
    /// Generate the cipher from private key of server, public key of client to be sent to client.
    pub fn new(key: &Combinedkey, pubkey: &Combinedpub) -> Result<Combinedcipher, PqxError> {
        let mut rng = thread_rng();
        let (cipher, shared) = match encapsulate(&pubkey.kyber, &mut rng) {
            Ok(data) => data,
            Err(_) => return Err(PqxError::KyberError),
        };
        let mut result = [0u8; Self::KEYSIZE];
        result[..cipher.len()].copy_from_slice(&cipher);
        result[cipher.len()..]
            .copy_from_slice(x25519_dalek::PublicKey::from(&key.x25519).as_bytes());
        Ok(Combinedcipher {
            cipher: result,
            shared_secret: Some(shared),
        })
    }
    /// Get the cipher outside the structure (copy)
    pub fn getcipher(&self) -> [u8; Self::KEYSIZE] {
        self.cipher
    }
}
impl From<[u8; Combinedcipher::KEYSIZE]> for Combinedcipher {
    /// Allow to create the cipher from the value obtained from the server
    fn from(value: [u8; Combinedcipher::KEYSIZE]) -> Self {
        Combinedcipher {
            cipher: value,
            shared_secret: None,
        }
    }
}
/// Size of shared key wanted
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SHAREDSIZE {
    Low = 128,
    Med = 196,
    High = 256,
    VHigh = 384,
    VVHigh = 512,
}
impl Combinedshared {
    /// Length of the shared secret
    const SHAREDLEN: usize = KYBER_SSBYTES + X25519_BASEPOINT_BYTES.as_slice().len();
    /// Create the shared secret from cipher (client side)
    pub fn new(key: Combinedkey, cipher: Combinedcipher) -> Result<Self, PqxError> {
        let (cipher, pubkey) = cipher.cipher.split_at(KYBER_CIPHERTEXTBYTES);
        let pubkey: [u8; X25519_BASEPOINT_BYTES.as_slice().len()] =
            match pubkey[..X25519_BASEPOINT_BYTES.as_slice().len()].try_into() {
                Ok(pubkey) => pubkey,
                Err(_) => return Err(PqxError::InvalidInput),
            };
        let pubkey = x25519_dalek::PublicKey::from(pubkey);
        let diffie = key.x25519.diffie_hellman(&pubkey);
        let shared_secret = match decapsulate(cipher, &key.kyber.secret) {
            Ok(data) => data,
            Err(_) => return Err(PqxError::InvalidInput),
        };
        let mut combined: Vec<u8> = Vec::new();
        combined.extend_from_slice(&shared_secret);
        combined.extend_from_slice(diffie.as_bytes());
        let elem = Ok(Combinedshared {
            shared: Box::new(combined[..Self::SHAREDLEN].try_into().unwrap()),
        });
        combined.zeroize();
        elem
    }
    /// Retrieve the shared secret from generation (server side)
    pub fn getfromshared(
        shared: Combinedcipher,
        pubkey: Combinedpub,
        key: Combinedkey,
    ) -> Result<Self, PqxError> {
        let secret = match shared.shared_secret {
            Some(val) => val,
            None => return Err(PqxError::InvalidInput),
        };
        let mut combined: Vec<u8> = Vec::new();
        let diffie = key.x25519.diffie_hellman(&pubkey.x25519);
        combined.extend_from_slice(&secret);
        combined.extend_from_slice(diffie.as_bytes());
        let elem = Ok(Combinedshared {
            shared: Box::new(combined[..Combinedshared::SHAREDLEN].try_into().unwrap()),
        });
        combined.zeroize();
        elem
    }
    /// Get the wanted size of shared key (consumes the element)
    pub fn getshared(self, size: SHAREDSIZE) -> Finalkey {
        let element: Vec<u8> = match size {
            SHAREDSIZE::Low => {
                let mut sha = Sha256::digest(self.shared.as_ref()).to_vec();
                sha.truncate(128);
                sha
            }
            SHAREDSIZE::Med => {
                let mut sha = Sha256::digest(self.shared.as_ref()).to_vec();
                sha.truncate(196);
                sha
            }
            SHAREDSIZE::High => Sha256::digest(self.shared.as_ref()).to_vec(),
            SHAREDSIZE::VHigh => Sha384::digest(self.shared.as_ref()).to_vec(),
            SHAREDSIZE::VVHigh => Sha512::digest(self.shared.as_ref()).to_vec(),
        };
        Finalkey { shared: element }
    }
}
