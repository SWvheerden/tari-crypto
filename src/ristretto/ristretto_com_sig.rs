// Copyright 2021 The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    ristretto::{pedersen::PedersenCommitmentFactory, RistrettoPublicKey, RistrettoSecretKey},
    signature::commitment_signature::CommitmentSignature,
};

/// # A Commitment signature implementation on Ristretto
///
/// Find out more about Commitment signatures [here](https://eprint.iacr.org/2020/061.pdf) and
/// [here](https://documents.uow.edu.au/~wsusilo/ZCMS_IJNS08.pdf).
///
/// `RistrettoComSig` utilises the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek1)
/// implementation of `ristretto255` to provide Commitment Signature functionality utlizing Schnorr signatures.
///
/// In short, a Commitment Signature is made up of the tuple _(R, u, v)_, where _R_ is a random Pedersen commitment (of
/// two secret nonces) and _u_ and _v_ are the two publicly known private keys.
///
/// ## Creating signatures
///
/// You can create a `RistrettoComSig` from it's component parts:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
///
/// let r_pub_key = RistrettoPublicKey::from_hex("8063d85e151abee630e643e2b3dc47bfaeb8aa859c9d10d60847985f286aad19").unwrap();
/// let r_pub = HomomorphicCommitment::from_public_key(&r_pub_key);
/// let u = RistrettoSecretKey::from_bytes(b"10000000000000000000000010000000").unwrap();
/// let v = RistrettoSecretKey::from_bytes(b"a00000000000000000000000a0000000").unwrap();
/// let sig = RistrettoComSig::new(r_pub, u, v);
/// ```
///
/// or you can create a signature by signing a message with knowledge of a commitment:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::common::*;
/// # use digest::Digest;
///
/// let mut rng = rand::thread_rng();
/// let a_val = RistrettoSecretKey::random(&mut rng);
/// let x_val = RistrettoSecretKey::random(&mut rng);
/// let a_nonce = RistrettoSecretKey::random(&mut rng);
/// let x_nonce = RistrettoSecretKey::random(&mut rng);
/// let e = Blake256::digest(b"Small Gods");
/// let sig = RistrettoComSig::sign(a_val, x_val, a_nonce, x_nonce, &e);
/// ```
///
/// # Verifying signatures
///
/// Given a signature, (R,u,v) and a Challenge, e, you can verify that the signature is valid by calling the
/// `verify_challenge` method:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_crypto::ristretto::pedersen::*;
/// # use tari_crypto::commitment::HomomorphicCommitmentFactory;
/// # use tari_crypto::common::*;
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
///
/// let mut rng = rand::thread_rng();
/// let a_val = RistrettoSecretKey::random(&mut rng);
/// let x_val = RistrettoSecretKey::random(&mut rng);
/// let factory = PedersenCommitmentFactory::default();
/// let commitment = factory.commit(&x_val, &a_val);
/// let a_nonce = RistrettoSecretKey::random(&mut rng);
/// let x_nonce = RistrettoSecretKey::random(&mut rng);
/// let e = Blake256::digest(b"Maskerade");
/// let sig = RistrettoComSig::sign(a_val, x_val, a_nonce, x_nonce, &e).unwrap();
/// assert!(sig.verify_challenge(&commitment, &e));
/// ```
pub type RistrettoComSig = CommitmentSignature<RistrettoPublicKey, RistrettoSecretKey, PedersenCommitmentFactory>;

#[cfg(test)]
mod test {
    use crate::{
        commitment::HomomorphicCommitmentFactory,
        common::Blake256,
        keys::SecretKey,
        ristretto::{
            pedersen::PedersenCommitment,
            ristretto_com_sig::PedersenCommitmentFactory,
            RistrettoComSig,
            RistrettoSecretKey,
        },
    };
    use digest::Digest;
    use tari_utilities::ByteArray;

    #[test]
    fn default() {
        let sig = RistrettoComSig::default();
        let commitment = PedersenCommitment::default();
        let (_, sig_1, sig_2) = sig.get_complete_signature_tuple();
        assert_eq!(
            (sig_1, sig_2),
            (&RistrettoSecretKey::default(), &RistrettoSecretKey::default())
        );
        assert_eq!(sig.get_public_commitment_nonce(), &commitment);
    }

    // C = a*H + x*G     ... (Pedersen commitment to the value 'a')
    // R = k_2*H + k_1*G
    // u = k_1 + e.x
    // v = k_2 + e.a
    // signature = (R, u, v)
    /// Create a signature, and then verify it. Also checks that some invalid signatures fail to verify
    #[test]
    #[allow(non_snake_case)]
    fn sign_and_verify_message() {
        let mut rng = rand::thread_rng();
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let factory = PedersenCommitmentFactory::default();
        let commitment = factory.commit(&x_value, &a_value);

        let k_1 = RistrettoSecretKey::random(&mut rng);
        let k_2 = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment = factory.commit(&k_1, &k_2);

        let challange = Blake256::new()
            .chain(commitment.as_bytes())
            .chain(nonce_commitment.as_bytes())
            .chain(b"Small Gods")
            .result();
        let e_key = RistrettoSecretKey::from_bytes(&challange).unwrap();
        let u_value = &k_1 + e_key.clone() * &x_value;
        let v_value = &k_2 + e_key * &a_value;
        let sig = RistrettoComSig::sign(a_value, x_value, k_2, k_1, &challange).unwrap();
        let R_calc = sig.get_public_commitment_nonce();
        assert_eq!(nonce_commitment, *R_calc);
        let (_, sig_1, sig_2) = sig.get_complete_signature_tuple();
        assert_eq!((sig_1, sig_2), (&u_value, &v_value));
        assert!(sig.verify_challenge(&commitment, &challange));
        // Doesn't work for invalid credentials
        assert!(!sig.verify_challenge(&nonce_commitment, &challange));
        // Doesn't work for different challenge
        let wrong_challenge = Blake256::digest(b"Guards! Guards!");
        assert!(!sig.verify_challenge(&commitment, &wrong_challenge));
    }

    // /// This test checks that the linearity of Schnorr signatures hold, i.e. that s = s1 + s2 is validated by R1 + R2
    // /// and P1 + P2. We do this by hand here rather than using the APIs to guard against regressions
    // #[test]
    // #[allow(non_snake_case)]
    // fn test_signature_addition() {
    //     let mut rng = rand::thread_rng();
    //     // Alice and Bob generate some keys and nonces
    //     let (k1, P1) = RistrettoPublicKey::random_keypair(&mut rng);
    //     let (r1, R1) = RistrettoPublicKey::random_keypair(&mut rng);
    //     let (k2, P2) = RistrettoPublicKey::random_keypair(&mut rng);
    //     let (r2, R2) = RistrettoPublicKey::random_keypair(&mut rng);
    //     // Each of them creates the Challenge = H(R1 || R2 || P1 || P2 || m)
    //     let e = Blake256::new()
    //         .chain(R1.as_bytes())
    //         .chain(R2.as_bytes())
    //         .chain(P1.as_bytes())
    //         .chain(P2.as_bytes())
    //         .chain(b"Moving Pictures")
    //         .result();
    //     // Calculate Alice's signature
    //     let s1 = RistrettoSchnorr::sign(k1, r1, &e).unwrap();
    //     // Calculate Bob's signature
    //     let s2 = RistrettoSchnorr::sign(k2, r2, &e).unwrap();
    //     // Now add the two signatures together
    //     let s_agg = &s1 + &s2;
    //     // Check that the multi-sig verifies
    //     assert!(s_agg.verify_challenge(&(P1 + P2), &e));
    // }
    //
    // /// Ristretto scalars have a max value 2^255. This test checks that hashed messages above this value can still be
    // /// signed as a result of applying modulo arithmetic on the challenge value
    // #[test]
    // fn challenge_from_invalid_scalar() {
    //     let mut rng = rand::thread_rng();
    //     let m = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
    //     let k = RistrettoSecretKey::random(&mut rng);
    //     let r = RistrettoSecretKey::random(&mut rng);
    //     assert!(RistrettoSchnorr::sign(k, r, &m).is_ok());
    // }
}
