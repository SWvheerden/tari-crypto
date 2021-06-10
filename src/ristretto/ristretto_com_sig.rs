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
/// let r_pub = HomomorphicCommitment::from_hex("8063d85e151abee630e643e2b3dc47bfaeb8aa859c9d10d60847985f286aad19").unwrap();
/// let u = RistrettoSecretKey::from_bytes(b"10000000000000000000000010000000").unwrap();
/// let v = RistrettoSecretKey::from_bytes(b"a00000000000000000000000a0000000").unwrap();
/// let sig = RistrettoComSig::new(r_pub, u, v);
/// ```
///
/// or you can create a signature for a commitment by signing a message with knowledge of the commitment and then
/// verify it by calling the `verify_challenge` method:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::common::*;
/// # use digest::Digest;
/// # use tari_crypto::commitment::HomomorphicCommitmentFactory;
/// # use tari_crypto::ristretto::pedersen::*;
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
///
/// # Verifying signatures
///
/// Given a signature, (R,u,v), a commitment C and a Challenge, e, you can verify that the signature is valid by
/// calling the `verify_challenge` method:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_crypto::ristretto::pedersen::*;
/// # use tari_crypto::common::*;
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
///
/// let commitment = HomomorphicCommitment::from_hex("d6cca5cc4cc302c1854a118221d6cf64d100b7da76665dae5199368f3703c665").unwrap();
/// let r_nonce = HomomorphicCommitment::from_hex("9607f72d84d704825864a4455c2325509ecc290eb9419bbce7ff05f1f578284c").unwrap();
/// let u = RistrettoSecretKey::from_hex("0fd60e6479507fec35a46d2ec9da0ae300e9202e613e99b8f2b01d7ef6eccc02").unwrap();
/// let v = RistrettoSecretKey::from_hex("9ae6621dd99ecc252b90a0eb69577c6f3d2e1e8abcdd43bfd0297afadf95fb0b").unwrap();
/// let sig = RistrettoComSig::new(r_nonce, u, v);
/// let e = Blake256::digest(b"Maskerade");
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
    use tari_utilities::{hex::from_hex, ByteArray};

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

    /// This test checks that the linearity of commitment Schnorr signatures hold, i.e. that s = s1 + s2 is validated by
    /// R1 + R2 and C1 + C2. We do this by hand here rather than using the APIs to guard against regressions
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        let mut rng = rand::thread_rng();
        let factory = PedersenCommitmentFactory::default();
        // Alice generate some keys and nonces
        let a_value_alice = RistrettoSecretKey::random(&mut rng);
        let x_value_alice = RistrettoSecretKey::random(&mut rng);
        let commitment_alice = factory.commit(&x_value_alice, &a_value_alice);
        let k_1_alice = RistrettoSecretKey::random(&mut rng);
        let k_2_alice = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment_alice = factory.commit(&k_1_alice, &k_2_alice);
        // Alice generate some keys and nonces
        let a_value_bob = RistrettoSecretKey::random(&mut rng);
        let x_value_bob = RistrettoSecretKey::random(&mut rng);
        let commitment_bob = factory.commit(&x_value_bob, &a_value_bob);
        let k_1_bob = RistrettoSecretKey::random(&mut rng);
        let k_2_bob = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment_bob = factory.commit(&k_1_bob, &k_2_bob);
        // Each of them creates the Challenge committing to both commitments of both parties
        let challange = Blake256::new()
            .chain(commitment_alice.as_bytes())
            .chain(commitment_bob.as_bytes())
            .chain(nonce_commitment_alice.as_bytes())
            .chain(nonce_commitment_bob.as_bytes())
            .chain(b"Moving Pictures")
            .result();
        // Calculate Alice's signature
        let sig_alice = RistrettoComSig::sign(a_value_alice, x_value_alice, k_2_alice, k_1_alice, &challange).unwrap();
        // Calculate Bob's signature
        let sig_bob = RistrettoComSig::sign(a_value_bob, x_value_bob, k_2_bob, k_1_bob, &challange).unwrap();
        // Now add the two signatures together
        let s_agg = &sig_alice + &sig_bob;
        // Check that the multi-sig verifies
        let combined_commitment = &commitment_alice + &commitment_bob;
        assert!(s_agg.verify_challenge(&combined_commitment, &challange));
    }

    /// Ristretto scalars have a max value 2^255. This test checks that hashed messages above this value can still be
    /// signed as a result of applying modulo arithmetic on the challenge value
    #[test]
    fn challenge_from_invalid_scalar() {
        let mut rng = rand::thread_rng();
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let message = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let k_1 = RistrettoSecretKey::random(&mut rng);
        let k_2 = RistrettoSecretKey::random(&mut rng);
        assert!(RistrettoComSig::sign(a_value, x_value, k_2, k_1, &message).is_ok());
    }
}
