#[macro_use]
pub mod logger;
mod commitment;
mod constants;
#[macro_use]
mod datastructures;
#[macro_use]
mod helpers;
mod hash;
pub mod issuer;
pub mod prover;
pub mod verifier;

use bn::{BigNumber, BigNumberContext};
use errors::IndyCryptoError;
use pair::*;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::Hash;

/// Creates random nonce
///
/// # Example
/// ```
/// use indy_crypto::cl::new_nonce;
///
/// let _nonce = new_nonce().unwrap();
/// ```
pub fn new_nonce() -> Result<Nonce, IndyCryptoError> {
    Ok(helpers::bn_rand(constants::LARGE_NONCE)?)
}

/// A list of attributes a Credential is based on.
#[derive(Debug, Clone)]
pub struct CredentialSchema {
    attrs: BTreeSet<String>, /* attr names */
}

/// A Builder of `Credential Schema`.
#[derive(Debug)]
pub struct CredentialSchemaBuilder {
    attrs: BTreeSet<String>, /* attr names */
}

impl CredentialSchemaBuilder {
    pub fn new() -> Result<CredentialSchemaBuilder, IndyCryptoError> {
        Ok(CredentialSchemaBuilder {
            attrs: BTreeSet::new(),
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> Result<CredentialSchema, IndyCryptoError> {
        Ok(CredentialSchema { attrs: self.attrs })
    }
}

#[derive(Debug, Clone)]
pub struct NonCredentialSchema {
    attrs: BTreeSet<String>,
}

#[derive(Debug)]
pub struct NonCredentialSchemaBuilder {
    attrs: BTreeSet<String>,
}

impl NonCredentialSchemaBuilder {
    pub fn new() -> Result<NonCredentialSchemaBuilder, IndyCryptoError> {
        Ok(NonCredentialSchemaBuilder {
            attrs: BTreeSet::new(),
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> Result<NonCredentialSchema, IndyCryptoError> {
        Ok(NonCredentialSchema { attrs: self.attrs })
    }
}

/// The m value for attributes,
/// commitments also store a blinding factor
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum CredentialValue {
    Known {
        value: BigNumber,
    }, //Issuer and Prover know these
    Hidden {
        value: BigNumber,
    }, //Only known to Prover who binds these into the U factor
    Commitment {
        value: BigNumber,
        blinding_factor: BigNumber,
    }, //Only known to Prover, not included in the credential, used for proving knowledge during issuance
}

impl CredentialValue {
    pub fn clone(&self) -> Result<CredentialValue, IndyCryptoError> {
        Ok(match *self {
            CredentialValue::Known { ref value } => CredentialValue::Known {
                value: value.clone()?,
            },
            CredentialValue::Hidden { ref value } => CredentialValue::Hidden {
                value: value.clone()?,
            },
            CredentialValue::Commitment {
                ref value,
                ref blinding_factor,
            } => CredentialValue::Commitment {
                value: value.clone()?,
                blinding_factor: blinding_factor.clone()?,
            },
        })
    }

    pub fn is_known(&self) -> bool {
        match *self {
            CredentialValue::Known { .. } => true,
            _ => false,
        }
    }

    pub fn is_hidden(&self) -> bool {
        match *self {
            CredentialValue::Hidden { .. } => true,
            _ => false,
        }
    }

    pub fn is_commitment(&self) -> bool {
        match *self {
            CredentialValue::Commitment { .. } => true,
            _ => false,
        }
    }

    pub fn value(&self) -> &BigNumber {
        match *self {
            CredentialValue::Known { ref value } => value,
            CredentialValue::Hidden { ref value } => value,
            CredentialValue::Commitment { ref value, .. } => value,
        }
    }
}

/// Values of attributes from `Claim Schema` (must be integers).
#[derive(Debug)]
pub struct CredentialValues {
    attrs_values: BTreeMap<String, CredentialValue>,
}

impl CredentialValues {
    pub fn clone(&self) -> Result<CredentialValues, IndyCryptoError> {
        Ok(CredentialValues {
            attrs_values: clone_credential_value_map(&self.attrs_values)?,
        })
    }
}

/// A Builder of `Credential Values`.
#[derive(Debug)]
pub struct CredentialValuesBuilder {
    attrs_values: BTreeMap<String, CredentialValue>, /* attr_name -> int representation of value */
}

impl CredentialValuesBuilder {
    pub fn new() -> Result<CredentialValuesBuilder, IndyCryptoError> {
        Ok(CredentialValuesBuilder {
            attrs_values: BTreeMap::new(),
        })
    }

    pub fn add_dec_known(&mut self, attr: &str, value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Known {
                value: BigNumber::from_dec(value)?,
            },
        );
        Ok(())
    }

    pub fn add_dec_hidden(&mut self, attr: &str, value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Hidden {
                value: BigNumber::from_dec(value)?,
            },
        );
        Ok(())
    }

    pub fn add_dec_commitment(
        &mut self,
        attr: &str,
        value: &str,
        blinding_factor: &str,
    ) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Commitment {
                value: BigNumber::from_dec(value)?,
                blinding_factor: BigNumber::from_dec(blinding_factor)?,
            },
        );
        Ok(())
    }

    pub fn add_value_known(
        &mut self,
        attr: &str,
        value: &BigNumber,
    ) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Known {
                value: value.clone()?,
            },
        );
        Ok(())
    }

    pub fn add_value_hidden(
        &mut self,
        attr: &str,
        value: &BigNumber,
    ) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Hidden {
                value: value.clone()?,
            },
        );
        Ok(())
    }

    pub fn add_value_commitment(
        &mut self,
        attr: &str,
        value: &BigNumber,
        blinding_factor: &BigNumber,
    ) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Commitment {
                value: value.clone()?,
                blinding_factor: blinding_factor.clone()?,
            },
        );
        Ok(())
    }

    pub fn finalize(self) -> Result<CredentialValues, IndyCryptoError> {
        Ok(CredentialValues {
            attrs_values: self.attrs_values,
        })
    }
}

/// `Issuer Public Key` contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
/// These keys are used to proof that credential was issued and doesn’t revoked by this issuer.
/// Issuer keys have global identifier that must be known to all parties.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct CredentialPublicKey {
    p_key: CredentialPrimaryPublicKey,
    r_key: Option<CredentialRevocationPublicKey>,
}

impl CredentialPublicKey {
    pub fn clone(&self) -> Result<CredentialPublicKey, IndyCryptoError> {
        Ok(CredentialPublicKey {
            p_key: self.p_key.clone()?,
            r_key: self.r_key.clone(),
        })
    }

    pub fn get_primary_key(&self) -> Result<CredentialPrimaryPublicKey, IndyCryptoError> {
        Ok(self.p_key.clone()?)
    }

    pub fn get_revocation_key(
        &self,
    ) -> Result<Option<CredentialRevocationPublicKey>, IndyCryptoError> {
        Ok(self.r_key.clone())
    }

    pub fn build_from_parts(
        p_key: &CredentialPrimaryPublicKey,
        r_key: Option<&CredentialRevocationPublicKey>,
    ) -> Result<CredentialPublicKey, IndyCryptoError> {
        Ok(CredentialPublicKey {
            p_key: p_key.clone()?,
            r_key: r_key.map(|key| key.clone()),
        })
    }
}

/// `Issuer Private Key`: contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialPrivateKey {
    p_key: CredentialPrimaryPrivateKey,
    r_key: Option<CredentialRevocationPrivateKey>,
}

/// Issuer's "Public Key" is used to verify the Issuer's signature over the Credential's attributes' values (primary credential).
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialPrimaryPublicKey {
    n: BigNumber,
    s: BigNumber,
    r: HashMap<String /* attr_name */, BigNumber>,
    rctxt: BigNumber,
    z: BigNumber,
}

impl CredentialPrimaryPublicKey {
    pub fn clone(&self) -> Result<CredentialPrimaryPublicKey, IndyCryptoError> {
        Ok(CredentialPrimaryPublicKey {
            n: self.n.clone()?,
            s: self.s.clone()?,
            r: clone_bignum_map(&self.r)?,
            rctxt: self.rctxt.clone()?,
            z: self.z.clone()?,
        })
    }
}

//impl<'a> ::serde::de::Deserialize<'a> for CredentialPrimaryPublicKey {
//    fn deserialize<D: ::serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
//        #[derive(Deserialize)]
//        struct CredentialPrimaryPublicKeyV1 {
//            n: BigNumber,
//            s: BigNumber,
//            r: HashMap<String /* attr_name */, BigNumber>,
//            rctxt: BigNumber,
//            #[serde(default)]
//            rms: BigNumber,
//            z: BigNumber,
//        }
//
//        let mut helper = CredentialPrimaryPublicKeyV1::deserialize(deserializer)?;
//        if helper.rms != BigNumber::default() {
//            helper.r.insert("master_secret".to_string(), helper.rms);
//        }
//        Ok(CredentialPrimaryPublicKey {
//            n: helper.n,
//            s: helper.s,
//            rctxt: helper.rctxt,
//            z: helper.z,
//            r: helper.r,
//        })
//    }
//}

/// Issuer's "Private Key" used for signing Credential's attributes' values (primary credential)
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialPrimaryPrivateKey {
    p: BigNumber,
    q: BigNumber,
}

/// `Primary Public Key Metadata` required for building of Proof Correctness of `Issuer Public Key`
#[derive(Debug)]
pub struct CredentialPrimaryPublicKeyMetadata {
    xz: BigNumber,
    xr: HashMap<String, BigNumber>,
}

/// Proof of `Issuer Public Key` correctness
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialKeyCorrectnessProof {
    c: BigNumber,
    xz_cap: BigNumber,
    xr_cap: Vec<(String, BigNumber)>,
}

/// `Revocation Public Key` is used to verify that credential was'nt revoked by Issuer.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CredentialRevocationPublicKey {
    g: PointG1,
    g_dash: PointG2,
    h: PointG1,
    h0: PointG1,
    h1: PointG1,
    h2: PointG1,
    htilde: PointG1,
    h_cap: PointG2,
    u: PointG2,
    pk: PointG1,
    y: PointG2,
}

/// `Revocation Private Key` is used for signing Credential.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRevocationPrivateKey {
    x: GroupOrderElement,
    sk: GroupOrderElement,
}

pub type Accumulator = PointG2;

/// `Revocation Registry` contains accumulator.
/// Must be published by Issuer on a tamper-evident and highly available storage
/// Used by prover to prove that a credential hasn't revoked by the issuer
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationRegistry {
    accum: Accumulator,
}

impl From<RevocationRegistryDelta> for RevocationRegistry {
    fn from(rev_reg_delta: RevocationRegistryDelta) -> RevocationRegistry {
        RevocationRegistry {
            accum: rev_reg_delta.accum,
        }
    }
}

/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_accum: Option<Accumulator>,
    accum: Accumulator,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    issued: HashSet<u32>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    revoked: HashSet<u32>,
}

impl RevocationRegistryDelta {
    pub fn from_parts(
        rev_reg_from: Option<&RevocationRegistry>,
        rev_reg_to: &RevocationRegistry,
        issued: &HashSet<u32>,
        revoked: &HashSet<u32>,
    ) -> RevocationRegistryDelta {
        RevocationRegistryDelta {
            prev_accum: rev_reg_from.map(|rev_reg| rev_reg.accum),
            accum: rev_reg_to.accum.clone(),
            issued: issued.clone(),
            revoked: revoked.clone(),
        }
    }

    pub fn merge(&mut self, other_delta: &RevocationRegistryDelta) -> Result<(), IndyCryptoError> {
        if other_delta.prev_accum.is_none() || self.accum != other_delta.prev_accum.unwrap() {
            return Err(IndyCryptoError::InvalidStructure(format!(
                "Deltas can not be merged."
            )));
        }

        self.accum = other_delta.accum;

        self.issued
            .extend(other_delta.issued.difference(&self.revoked));

        self.revoked
            .extend(other_delta.revoked.difference(&self.issued));

        for index in other_delta.revoked.iter() {
            self.issued.remove(index);
        }

        for index in other_delta.issued.iter() {
            self.revoked.remove(index);
        }

        Ok(())
    }
}

/// `Revocation Key Public` Accumulator public key.
/// Must be published together with Accumulator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationKeyPublic {
    z: Pair,
}

/// `Revocation Key Private` Accumulator primate key.
#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationKeyPrivate {
    gamma: GroupOrderElement,
}

/// `Tail` point of curve used to update accumulator.
pub type Tail = PointG2;

impl Tail {
    fn new_tail(
        index: u32,
        g_dash: &PointG2,
        gamma: &GroupOrderElement,
    ) -> Result<Tail, IndyCryptoError> {
        let i_bytes = helpers::transform_u32_to_array_of_u8(index);
        let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
        pow = gamma.pow_mod(&pow)?;
        Ok(g_dash.mul(&pow)?)
    }
}

/// Generator of `Tail's`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationTailsGenerator {
    size: u32,
    current_index: u32,
    g_dash: PointG2,
    gamma: GroupOrderElement,
}

impl RevocationTailsGenerator {
    fn new(max_cred_num: u32, gamma: GroupOrderElement, g_dash: PointG2) -> Self {
        RevocationTailsGenerator {
            size: 2 * max_cred_num + 1, /* Unused 0th + valuable 1..L + unused (L+1)th + valuable (L+2)..(2L) */
            current_index: 0,
            gamma,
            g_dash,
        }
    }

    pub fn count(&self) -> u32 {
        self.size - self.current_index
    }

    pub fn next(&mut self) -> Result<Option<Tail>, IndyCryptoError> {
        if self.current_index >= self.size {
            return Ok(None);
        }

        let tail = Tail::new_tail(self.current_index, &self.g_dash, &self.gamma)?;

        self.current_index += 1;

        Ok(Some(tail))
    }
}

pub trait RevocationTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail))
        -> Result<(), IndyCryptoError>;
}

/// Simple implementation of `RevocationTailsAccessor` that stores all tails as BTreeMap.
#[derive(Debug, Clone)]
pub struct SimpleTailsAccessor {
    tails: Vec<Tail>,
}

impl RevocationTailsAccessor for SimpleTailsAccessor {
    fn access_tail(
        &self,
        tail_id: u32,
        accessor: &mut FnMut(&Tail),
    ) -> Result<(), IndyCryptoError> {
        Ok(accessor(&self.tails[tail_id as usize]))
    }
}

impl SimpleTailsAccessor {
    pub fn new(
        rev_tails_generator: &mut RevocationTailsGenerator,
    ) -> Result<SimpleTailsAccessor, IndyCryptoError> {
        let mut tails: Vec<Tail> = Vec::new();
        while let Some(tail) = rev_tails_generator.next()? {
            tails.push(tail);
        }
        Ok(SimpleTailsAccessor { tails })
    }
}

/// Issuer's signature over Credential attribute values.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialSignature {
    p_credential: PrimaryCredentialSignature,
    r_credential: Option<NonRevocationCredentialSignature>, /* will be used to proof is credential revoked preparation */
}

impl CredentialSignature {
    pub fn extract_index(&self) -> Option<u32> {
        self.r_credential
            .as_ref()
            .map(|r_credential| r_credential.i)
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryCredentialSignature {
    m_2: BigNumber,
    a: BigNumber,
    e: BigNumber,
    v: BigNumber,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonRevocationCredentialSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    vr_prime_prime: GroupOrderElement,
    witness_signature: WitnessSignature,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SignatureCorrectnessProof {
    se: BigNumber,
    c: BigNumber,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Witness {
    omega: PointG2,
}

impl Witness {
    pub fn new<RTA>(
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg_delta: &RevocationRegistryDelta,
        rev_tails_accessor: &RTA,
    ) -> Result<Witness, IndyCryptoError>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!("Witness::new: >>> rev_idx: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, issuance_by_default, rev_reg_delta);

        let mut omega = PointG2::new_inf()?;

        let mut issued = if issuance_by_default {
            (1..max_cred_num + 1)
                .collect::<HashSet<u32>>()
                .difference(&rev_reg_delta.revoked)
                .cloned()
                .collect::<HashSet<u32>>()
        } else {
            rev_reg_delta.issued.clone()
        };

        issued.remove(&rev_idx);
        for j in issued.iter() {
            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega = omega.add(tail).unwrap();
            })?;
        }

        let witness = Witness { omega };

        trace!("Witness::new: <<< witness: {:?}", witness);

        Ok(witness)
    }

    pub fn update<RTA>(
        &mut self,
        rev_idx: u32,
        max_cred_num: u32,
        rev_reg_delta: &RevocationRegistryDelta,
        rev_tails_accessor: &RTA,
    ) -> Result<(), IndyCryptoError>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "Witness::update: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
            rev_idx,
            max_cred_num,
            rev_reg_delta
        );

        let mut omega_denom = PointG2::new_inf()?;
        for j in rev_reg_delta.revoked.iter() {
            if rev_idx.eq(j) {
                continue;
            }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_denom = omega_denom.add(tail).unwrap();
            })?;
        }

        let mut omega_num = PointG2::new_inf()?;
        for j in rev_reg_delta.issued.iter() {
            if rev_idx.eq(j) {
                continue;
            }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_num = omega_num.add(tail).unwrap();
            })?;
        }

        let new_omega: PointG2 = self.omega.add(&omega_num.sub(&omega_denom)?)?;

        self.omega = new_omega;

        trace!("Witness::update: <<<");

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WitnessSignature {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1,
}

/// Secret key encoded in a credential that is used to prove that prover owns the credential; can be used to
/// prove linkage across credentials.
/// Prover blinds master secret, generating `BlindedCredentialSecrets` and `CredentialSecretsBlindingFactors` (blinding factors)
/// and sends the `BlindedCredentialSecrets` to Issuer who then encodes it credential creation.
/// The blinding factors are used by Prover for post processing of issued credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecret {
    ms: BigNumber,
}

impl MasterSecret {
    pub fn clone(&self) -> Result<MasterSecret, IndyCryptoError> {
        Ok(MasterSecret {
            ms: self.ms.clone()?,
        })
    }

    pub fn value(&self) -> Result<BigNumber, IndyCryptoError> {
        Ok(self.ms.clone()?)
    }
}

/// Blinded Master Secret uses by Issuer in credential creation.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlindedCredentialSecrets {
    u: BigNumber,
    ur: Option<PointG1>,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, BigNumber>,
}

/// `CredentialSecretsBlindingFactors` used by Prover for post processing of credentials received from Issuer.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialSecretsBlindingFactors {
    v_prime: BigNumber,
    vr_prime: Option<GroupOrderElement>,
}

#[derive(Eq, PartialEq, Debug)]
pub struct PrimaryBlindedCredentialSecretsFactors {
    u: BigNumber,
    v_prime: BigNumber,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, BigNumber>,
}

#[derive(Debug)]
pub struct RevocationBlindedCredentialSecretsFactors {
    ur: PointG1,
    vr_prime: GroupOrderElement,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BlindedCredentialSecretsCorrectnessProof {
    c: BigNumber,                        // Fiat-Shamir challenge hash
    v_dash_cap: BigNumber, // Value to prove knowledge of `u` construction in `BlindedCredentialSecrets`
    m_caps: BTreeMap<String, BigNumber>, // Values for proving knowledge of committed values
    r_caps: BTreeMap<String, BigNumber>, // Blinding values for m_caps
}

/// “Sub Proof Request” - input to create a Proof for a credential;
/// Contains attributes to be revealed and predicates.
#[derive(Debug, Clone)]
pub struct SubProofRequest {
    revealed_attrs: BTreeSet<String>,
    predicates: BTreeSet<Predicate>,
}

/// Builder of “Sub Proof Request”.
#[derive(Debug)]
pub struct SubProofRequestBuilder {
    value: SubProofRequest,
}

impl SubProofRequestBuilder {
    pub fn new() -> Result<SubProofRequestBuilder, IndyCryptoError> {
        Ok(SubProofRequestBuilder {
            value: SubProofRequest {
                revealed_attrs: BTreeSet::new(),
                predicates: BTreeSet::new(),
            },
        })
    }

    pub fn add_revealed_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn add_predicate(
        &mut self,
        attr_name: &str,
        p_type: &str,
        value: i64,
    ) -> Result<(), IndyCryptoError> {
        let p_type = match p_type {
            "GE" => PredicateType::GE,
            "LE" => PredicateType::LE,
            "GT" => PredicateType::GT,
            "LT" => PredicateType::LT,
            p_type => {
                return Err(IndyCryptoError::InvalidStructure(format!(
                    "Invalid predicate type: {:?}",
                    p_type
                )))
            }
        };

        let predicate = Predicate {
            attr_name: attr_name.to_owned(),
            p_type,
            value,
        };

        self.value.predicates.insert(predicate);
        Ok(())
    }

    pub fn finalize(self) -> Result<SubProofRequest, IndyCryptoError> {
        Ok(self.value)
    }
}

/// Some condition that must be satisfied.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct Predicate {
    attr_name: String,
    p_type: PredicateType,
    value: i64,
}

impl Predicate {
    pub fn get_delta(&self, attr_value: i64) -> i64 {
        match self.p_type {
            PredicateType::GE => attr_value - self.value,
            PredicateType::GT => attr_value - self.value - 1,
            PredicateType::LE => self.value - attr_value,
            PredicateType::LT => self.value - attr_value - 1,
        }
    }

    pub fn get_delta_prime(&self) -> Result<BigNumber, IndyCryptoError> {
        match self.p_type {
            PredicateType::GE => BigNumber::from_dec(&self.value.to_string()),
            PredicateType::GT => BigNumber::from_dec(&(self.value + 1).to_string()),
            PredicateType::LE => BigNumber::from_dec(&self.value.to_string()),
            PredicateType::LT => BigNumber::from_dec(&(self.value - 1).to_string()),
        }
    }

    pub fn is_less(&self) -> bool {
        match self.p_type {
            PredicateType::GE | PredicateType::GT => false,
            PredicateType::LE | PredicateType::LT => true,
        }
    }
}

/// Condition type
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub enum PredicateType {
    GE,
    LE,
    GT,
    LT,
}

/// Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
/// 1) Knows signature over credentials issued with specific issuer keys (identified by key id)
/// 2) Credential contains attributes with specific values that prover wants to disclose
/// 3) Credential contains attributes with valid predicates that verifier wants the prover to satisfy.
#[derive(Debug, Deserialize, Serialize)]
pub struct Proof {
    proofs: Vec<SubProof>,
    aggregated_proof: AggregatedProof,
}

impl Proof {
    pub fn get_revealed_attrs_value(&self) -> Result<Vec<(String, BigNumber)>, IndyCryptoError> {
        let mut revealed_attrs: Vec<(String, BigNumber)> = Vec::new();
        for idx in 0..self.proofs.len() {
            let proof_item = &self.proofs[idx];
            let primary_proof = &proof_item.primary_proof.eq_proof;
            let attrs = &primary_proof.revealed_attrs;
            let mut attr_set: BTreeMap<String, BigNumber> = BTreeMap::new();
            for (key, value) in attrs {
                revealed_attrs.push((key.clone(), value.clone()?));
            }
        }
        Ok(revealed_attrs)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubProof {
    primary_proof: PrimaryProof,
    non_revoc_proof: Option<NonRevocProof>,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AggregatedProof {
    c_hash: BigNumber,
    c_list: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryProof {
    eq_proof: PrimaryEqualProof,
    ne_proofs: Vec<PrimaryPredicateInequalityProof>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryEqualProof {
    revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
    a_prime: BigNumber,
    e: BigNumber,
    v: BigNumber,
    m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
    m2: BigNumber,
}

//impl<'a> ::serde::de::Deserialize<'a> for PrimaryEqualProof {
//    fn deserialize<D: ::serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
//        #[derive(Deserialize)]
//        struct PrimaryEqualProofV1 {
//            revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
//            a_prime: BigNumber,
//            e: BigNumber,
//            v: BigNumber,
//            m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
//            #[serde(default)]
//            m1: BigNumber,
//            m2: BigNumber,
//        }
//
//        let mut helper = PrimaryEqualProofV1::deserialize(deserializer)?;
//        if helper.m1 != BigNumber::default() {
//            helper.m.insert("master_secret".to_string(), helper.m1);
//        }
//        Ok(PrimaryEqualProof {
//            revealed_attrs: helper.revealed_attrs,
//            a_prime: helper.a_prime,
//            e: helper.e,
//            v: helper.v,
//            m: helper.m,
//            m2: helper.m2,
//        })
//    }
//}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryPredicateInequalityProof {
    u: HashMap<String, BigNumber>,
    r: HashMap<String, BigNumber>,
    mj: BigNumber,
    alpha: BigNumber,
    t: HashMap<String, BigNumber>,
    predicate: Predicate,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NonRevocProof {
    x_list: NonRevocProofXList,
    c_list: NonRevocProofCList,
}

#[derive(Debug)]
pub struct InitProof {
    primary_init_proof: PrimaryInitProof,
    non_revoc_init_proof: Option<NonRevocInitProof>,
    credential_values: CredentialValues,
    sub_proof_request: SubProofRequest,
    credential_schema: CredentialSchema,
    non_credential_schema: NonCredentialSchema,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryInitProof {
    eq_proof: PrimaryEqualInitProof,
    ne_proofs: Vec<PrimaryPredicateInequalityInitProof>,
}

impl PrimaryInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let mut c_list: Vec<Vec<u8>> = self.eq_proof.as_list()?;
        for ne_proof in self.ne_proofs.iter() {
            c_list.append_vec(ne_proof.as_list()?)?;
        }
        Ok(c_list)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let mut tau_list: Vec<Vec<u8>> = self.eq_proof.as_tau_list()?;
        for ne_proof in self.ne_proofs.iter() {
            tau_list.append_vec(ne_proof.as_tau_list()?)?;
        }
        Ok(tau_list)
    }
}

#[derive(Debug)]
pub struct NonRevocInitProof {
    c_list_params: NonRevocProofXList,
    tau_list_params: NonRevocProofXList,
    c_list: NonRevocProofCList,
    tau_list: NonRevocProofTauList,
}

impl NonRevocInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.c_list.as_list()?;
        Ok(vec)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.tau_list.as_slice()?;
        Ok(vec)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryEqualInitProof {
    a_prime: BigNumber,
    t: BigNumber,
    e_tilde: BigNumber,
    e_prime: BigNumber,
    v_tilde: BigNumber,
    v_prime: BigNumber,
    m_tilde: HashMap<String, BigNumber>,
    m2_tilde: BigNumber,
    m2: BigNumber,
}

impl PrimaryEqualInitProof {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.a_prime.to_bytes()?])
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t.to_bytes()?])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryPredicateInequalityInitProof {
    c_list: Vec<BigNumber>,
    tau_list: Vec<BigNumber>,
    u: HashMap<String, BigNumber>,
    u_tilde: HashMap<String, BigNumber>,
    r: HashMap<String, BigNumber>,
    r_tilde: HashMap<String, BigNumber>,
    alpha_tilde: BigNumber,
    predicate: Predicate,
    t: HashMap<String, BigNumber>,
}

impl PrimaryPredicateInequalityInitProof {
    pub fn as_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.c_list)
    }

    pub fn as_tau_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.tau_list)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofXList {
    rho: GroupOrderElement,
    r: GroupOrderElement,
    r_prime: GroupOrderElement,
    r_prime_prime: GroupOrderElement,
    r_prime_prime_prime: GroupOrderElement,
    o: GroupOrderElement,
    o_prime: GroupOrderElement,
    m: GroupOrderElement,
    m_prime: GroupOrderElement,
    t: GroupOrderElement,
    t_prime: GroupOrderElement,
    m2: GroupOrderElement,
    s: GroupOrderElement,
    c: GroupOrderElement,
}

impl NonRevocProofXList {
    pub fn as_list(&self) -> Result<Vec<GroupOrderElement>, IndyCryptoError> {
        Ok(vec![
            self.rho,
            self.o,
            self.c,
            self.o_prime,
            self.m,
            self.m_prime,
            self.t,
            self.t_prime,
            self.m2,
            self.s,
            self.r,
            self.r_prime,
            self.r_prime_prime,
            self.r_prime_prime_prime,
        ])
    }

    pub fn from_list(seq: Vec<GroupOrderElement>) -> NonRevocProofXList {
        NonRevocProofXList {
            rho: seq[0],
            r: seq[10],
            r_prime: seq[11],
            r_prime_prime: seq[12],
            r_prime_prime_prime: seq[13],
            o: seq[1],
            o_prime: seq[3],
            m: seq[4],
            m_prime: seq[5],
            t: seq[6],
            t_prime: seq[7],
            m2: seq[8],
            s: seq[9],
            c: seq[2],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofCList {
    e: PointG1,
    d: PointG1,
    a: PointG1,
    g: PointG1,
    w: PointG2,
    s: PointG2,
    u: PointG2,
}

impl NonRevocProofCList {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![
            self.e.to_bytes()?,
            self.d.to_bytes()?,
            self.a.to_bytes()?,
            self.g.to_bytes()?,
            self.w.to_bytes()?,
            self.s.to_bytes()?,
            self.u.to_bytes()?,
        ])
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofTauList {
    t1: PointG1,
    t2: PointG1,
    t3: Pair,
    t4: Pair,
    t5: PointG1,
    t6: PointG1,
    t7: Pair,
    t8: Pair,
}

impl NonRevocProofTauList {
    pub fn as_slice(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![
            self.t1.to_bytes()?,
            self.t2.to_bytes()?,
            self.t3.to_bytes()?,
            self.t4.to_bytes()?,
            self.t5.to_bytes()?,
            self.t6.to_bytes()?,
            self.t7.to_bytes()?,
            self.t8.to_bytes()?,
        ])
    }
}

/// Random BigNumber that uses `Prover` for proof generation and `Verifier` for proof verification.
pub type Nonce = BigNumber;

#[derive(Debug)]
pub struct VerifiableCredential {
    pub_key: CredentialPublicKey,
    sub_proof_request: SubProofRequest,
    credential_schema: CredentialSchema,
    non_credential_schema: NonCredentialSchema,
    rev_key_pub: Option<RevocationKeyPublic>,
    rev_reg: Option<RevocationRegistry>,
}

trait BytesView {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError>;
}

impl BytesView for BigNumber {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for PointG1 {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for GroupOrderElement {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for Pair {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

trait AppendByteArray {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError>;
}

impl AppendByteArray for Vec<Vec<u8>> {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError> {
        for el in other.iter() {
            self.push(el.to_bytes()?);
        }
        Ok(())
    }
}

fn clone_bignum_map<K: Clone + Eq + Hash>(
    other: &HashMap<K, BigNumber>,
) -> Result<HashMap<K, BigNumber>, IndyCryptoError> {
    let mut res = HashMap::new();
    for (k, v) in other.iter() {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

fn clone_credential_value_map<K: Clone + Eq + Ord>(
    other: &BTreeMap<K, CredentialValue>,
) -> Result<BTreeMap<K, CredentialValue>, IndyCryptoError> {
    let mut res = BTreeMap::new();
    for (k, v) in other {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use self::issuer::Issuer;
    use self::prover::Prover;
    use self::verifier::Verifier;
    use super::*;
    use serde_json;

    #[test]
    fn multiple_predicates() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder
            .add_attr("funds_sold_and_securities_purchased")
            .unwrap();
        credential_schema_builder
            .add_attr("other_earning_assets")
            .unwrap();
        credential_schema_builder.add_attr("cash").unwrap();
        credential_schema_builder.add_attr("allowance").unwrap();
        credential_schema_builder.add_attr("total_assets").unwrap();
        credential_schema_builder
            .add_attr("domestic_interest_bearing_deposits")
            .unwrap();
        credential_schema_builder
            .add_attr("funds_purchased")
            .unwrap();
        credential_schema_builder
            .add_attr("long_term_debt")
            .unwrap();
        credential_schema_builder
            .add_attr("non_interest_bearing_liabilities")
            .unwrap();
        credential_schema_builder
            .add_attr("shareholder_equity")
            .unwrap();
        credential_schema_builder
            .add_attr("total_liabilities")
            .unwrap();

        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();
        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &master_secret.value().unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("funds_sold_and_securities_purchased", "50")
            .unwrap();
        credential_values_builder
            .add_dec_known("other_earning_assets", "60")
            .unwrap();
        credential_values_builder
            .add_dec_known("cash", "70")
            .unwrap();
        credential_values_builder
            .add_dec_known("allowance", "80")
            .unwrap();
        credential_values_builder
            .add_dec_known("total_assets", "260")
            .unwrap();

        credential_values_builder
            .add_dec_known("domestic_interest_bearing_deposits", "10")
            .unwrap();
        credential_values_builder
            .add_dec_known("funds_purchased", "20")
            .unwrap();
        credential_values_builder
            .add_dec_known("long_term_debt", "30")
            .unwrap();
        credential_values_builder
            .add_dec_known("non_interest_bearing_liabilities", "40")
            .unwrap();
        credential_values_builder
            .add_dec_known("shareholder_equity", "50")
            .unwrap();
        credential_values_builder
            .add_dec_known("total_liabilities", "150")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "b977afe22b5b446109797ad925d9f133fc33c1914081071295d2ac1ddce3385d",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder
            .add_revealed_attr("total_liabilities")
            .unwrap();

        sub_proof_request_builder
            .add_predicate("funds_sold_and_securities_purchased", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("funds_sold_and_securities_purchased", "GT", 0)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("other_earning_assets", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("cash", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("allowance", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("total_assets", "GT", 100)
            .unwrap();

        sub_proof_request_builder
            .add_predicate("domestic_interest_bearing_deposits", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("funds_purchased", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("long_term_debt", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("non_interest_bearing_liabilities", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("shareholder_equity", "LE", 100)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    extern crate bincode;

    #[test]
    fn demo() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let encoded1 = bincode::serialize(&cred_pub_key).unwrap();
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &master_secret.value().unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();
        let cred_pub_key: CredentialPublicKey = bincode::deserialize(&encoded1[..]).unwrap();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();
        println!("proof = {:?}", proof.get_revealed_attrs_value());

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[test]
    fn demo_revocation() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, issuance_by_default)
                .unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &master_secret.value().unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let credential_issuance_nonce = new_nonce().unwrap();

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(
                "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &cred_values,
                &cred_pub_key,
                &cred_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
                &simple_tail_accessor,
            )
            .unwrap();

        let witness = Witness::new(
            rev_idx,
            max_cred_num,
            issuance_by_default,
            &rev_reg_delta.unwrap(),
            &simple_tail_accessor,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &credential_issuance_nonce,
            Some(&rev_key_pub),
            Some(&rev_reg),
            Some(&witness),
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();
        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                Some(&rev_key_pub),
                Some(&rev_reg),
            )
            .unwrap();
        assert_eq!(
            true,
            proof_verifier.verify(&proof, &proof_request_nonce).unwrap()
        );
    }
}
