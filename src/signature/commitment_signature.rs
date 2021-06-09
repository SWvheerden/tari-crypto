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

//! Digital Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use crate::{
    commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
    keys::{PublicKey, SecretKey},
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Add, Mul},
};
use tari_utilities::{hex::Hex, ByteArray};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq, Deserialize, Serialize)]
pub enum CommitmentSignatureError {
    #[error("An invalid challenge was provided")]
    InvalidChallenge,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentSignature<P, K, C> {
    public_commitment_nonce: HomomorphicCommitment<P>,
    signature_u: K,
    signature_v: K,
    _commitment_factory: PhantomData<C>,
}

// C = a*H + x*G     ... (Pedersen commitment to the value 'a')
// R = k_2*H + k_1*G
// u = k_1 + e.x
// v = k_2 + e.a
// signature = (R, u, v)
impl<P, K, C> CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    pub fn new(public_commitment_nonce: HomomorphicCommitment<P>, signature_u: K, signature_v: K) -> Self {
        CommitmentSignature {
            public_commitment_nonce,
            signature_u,
            signature_v,
            _commitment_factory: PhantomData,
        }
    }

    pub fn calc_signature_verifier(&self) -> HomomorphicCommitment<P> {
        // v*H + u*G = Commitment
        let factory = C::default();
        factory.commit(&self.signature_u, &self.signature_v)
    }

    pub fn sign(
        secret_a: K,
        secret_x: K,
        nonce_a: K,
        nonce_x: K,
        challenge: &[u8],
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Add<Output = K> + Mul<P, Output = P> + Mul<Output = K>,
    {
        let e = match K::from_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(CommitmentSignatureError::InvalidChallenge),
        };
        let ea = e.clone() * secret_a;
        let ex = e * secret_x;

        let v = nonce_a.clone() + ea;
        let u = nonce_x.clone() + ex;

        let factory = C::default();
        let public_commitment_nonce = factory.commit(&nonce_x, &nonce_a);

        Ok(Self::new(public_commitment_nonce, u, v))
    }

    pub fn verify_challenge<'a>(&self, public_commitment: &'a HomomorphicCommitment<P>, challenge: &[u8]) -> bool
    where
        for<'b> &'b K: Mul<&'a HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    {
        let e = match K::from_bytes(&challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };

        self.verify(public_commitment, &e)
    }

    pub fn verify<'a>(&self, public_commitment: &'a HomomorphicCommitment<P>, challenge: &K) -> bool
    where
        for<'b> &'b K: Mul<&'a HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    {
        let lhs = self.calc_signature_verifier();
        let rhs = &self.public_commitment_nonce + challenge * public_commitment;
        // Implementors should make this a constant time comparison
        lhs == rhs
    }

    #[inline]
    pub fn get_signature(&self) -> (&K, &K) {
        (&self.signature_u, &self.signature_v)
    }

    #[inline]
    pub fn get_signature_u(&self) -> &K {
        &self.signature_u
    }

    #[inline]
    pub fn get_signature_v(&self) -> &K {
        &self.signature_v
    }

    #[inline]
    pub fn get_public_commitment_nonce(&self) -> &HomomorphicCommitment<P> {
        &self.public_commitment_nonce
    }
}

impl<'a, 'b, P, K, C> Add<&'b CommitmentSignature<P, K, C>> for &'a CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    &'a HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    K: SecretKey,
    &'a K: Add<&'b K, Output = K>,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    type Output = CommitmentSignature<P, K, C>;

    fn add(self, rhs: &'b CommitmentSignature<P, K, C>) -> CommitmentSignature<P, K, C> {
        let r_sum = self.get_public_commitment_nonce() + rhs.get_public_commitment_nonce();
        let s_u_sum = self.get_signature_u() + rhs.get_signature_u();
        let s_v_sum = self.get_signature_v() + rhs.get_signature_v();
        CommitmentSignature::new(r_sum, s_u_sum, s_v_sum)
    }
}

impl<'a, P, K, C> Add<CommitmentSignature<P, K, C>> for &'a CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    for<'b> &'a HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    K: SecretKey,
    for<'b> &'a K: Add<&'b K, Output = K>,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    type Output = CommitmentSignature<P, K, C>;

    fn add(self, rhs: CommitmentSignature<P, K, C>) -> CommitmentSignature<P, K, C> {
        let r_sum = self.get_public_commitment_nonce() + rhs.get_public_commitment_nonce();
        let s_u_sum = self.get_signature_u() + rhs.get_signature_u();
        let s_v_sum = self.get_signature_v() + rhs.get_signature_v();
        CommitmentSignature::new(r_sum, s_u_sum, s_v_sum)
    }
}

impl<P, K, C> Default for CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    fn default() -> Self {
        CommitmentSignature::new(HomomorphicCommitment::<P>::default(), K::default(), K::default())
    }
}

/// Provide an efficient ordering algorithm for Commitment signatures. It's probably not a good idea to implement `Ord`
/// for secret keys, but in this instance, the signature is publicly known and is simply a scalar, so we use the hex
/// representation of the scalar as the canonical ordering metric. This conversion is done if and only if the public
/// nonces are already equal, otherwise the public nonce ordering determines the CommitmentSignature order.
impl<P, K, C> Ord for CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .get_public_commitment_nonce()
            .cmp(&other.get_public_commitment_nonce())
        {
            Ordering::Equal => {
                let this_u = self.get_signature_u().to_hex();
                let that_u = other.get_signature_u().to_hex();
                match this_u.cmp(&that_u) {
                    Ordering::Equal => {
                        let this = self.get_signature_v().to_hex();
                        let that = other.get_signature_v().to_hex();
                        this.cmp(&that)
                    },
                    v => v,
                }
            },
            v => v,
        }
    }
}

impl<P, K, C> PartialOrd for CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K, C> PartialEq for CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_public_commitment_nonce()
            .eq(other.get_public_commitment_nonce()) &&
            self.get_signature_u().eq(other.get_signature_u()) &&
            self.get_signature_v().eq(other.get_signature_v())
    }
}

impl<P, K, C> Eq for CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
}

impl<P, K, C> Hash for CommitmentSignature<P, K, C>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    C: HomomorphicCommitmentFactory<P = P> + Default,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(
            &[
                self.get_public_commitment_nonce().as_bytes(),
                self.get_signature_u().as_bytes(),
                self.get_signature_v().as_bytes(),
            ]
            .concat(),
        )
    }
}
