use digest::Digest;
use sha2::Sha256;

use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey};

pub const MAX_AMOUNT_PER_OUTPUT: u64 = 1000;

/// The number curve_order-1 encoded as a secret key
pub const MINUS_ONE_KEY: SecretKey = SecretKey([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
]);

pub const GENERATOR_G : [u8;65] = [
    0x04,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8 
];

pub const GENERATOR_H : [u8;65] = [
    0x04,
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
    0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
    0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
];

#[derive (Copy, Clone)]
//pair of secp public keys which constitute a PublicKey and an ElGamal commitment in Quisquis
pub struct QPublicKey {      
    pub x : PublicKey,
    pub y : PublicKey,
}

impl QPublicKey {
    pub fn new() -> QPublicKey {
        QPublicKey {
            x : PublicKey::new(),
            y : PublicKey::new(),
        }
    }
}

pub fn amount_to_key (secp_inst: &Secp256k1, amount: u64) -> SecretKey {
    assert!(amount != 0);
    // Converting u64 amount to a scalar i.e. SecretKey
    let amount_as_bytes = amount.to_be_bytes();
    let mut amount_scalar_vec = vec![0u8; 24];
    amount_scalar_vec.extend_from_slice(&amount_as_bytes);
    let amount_scalar = SecretKey::from_slice(&secp_inst, amount_scalar_vec.as_slice()).unwrap();

    amount_scalar
}

//takes base and exp as arguments and returns base^exp
pub fn single_base_product (
    secp_inst: &Secp256k1, 
    base: PublicKey, 
    exp: SecretKey, 
    ) -> PublicKey {

    let mut exp_base = base.clone();
    exp_base.mul_assign(&secp_inst, &exp).unwrap();
    
    exp_base
}

//takes base1, base2, exp1, and exp2 as arguments and returns base1^exp1*base2^exp2
pub fn double_base_product (
    secp_inst: &Secp256k1, 
    base_1: PublicKey, 
    base_2: PublicKey, 
    exp_1: SecretKey, 
    exp_2: SecretKey,
    ) -> PublicKey {

    let mut exp1_base1 = base_1.clone();
    exp1_base1.mul_assign(&secp_inst, &exp_1).unwrap();
    let mut exp2_base2 = base_2.clone();
    exp2_base2.mul_assign(&secp_inst, &exp_2).unwrap();

    PublicKey::from_combination(&secp_inst, vec![&exp1_base1, &exp2_base2]).unwrap()
}

//takes base1, base2, base3, exp1, exp2, and exp3 as arguments and returns base1^exp1 * base2^exp2 * base3^exp3
pub fn triple_base_product (
    secp_inst: &Secp256k1, 
    base_1: PublicKey, 
    base_2: PublicKey, 
    base_3: PublicKey, 
    exp_1: SecretKey, 
    exp_2: SecretKey,
    exp_3: SecretKey,
    ) -> PublicKey {

    let mut exp1_base1 = base_1.clone();
    exp1_base1.mul_assign(&secp_inst, &exp_1).unwrap();
    let mut exp2_base2 = base_2.clone();
    exp2_base2.mul_assign(&secp_inst, &exp_2).unwrap();
    let mut exp3_base3 = base_3.clone();
    exp3_base3.mul_assign(&secp_inst, &exp_3).unwrap();

    PublicKey::from_combination(&secp_inst, vec![&exp1_base1, &exp2_base2, &exp3_base3]).unwrap()
}

//takes num and den as arguments and returns num * den^-1
pub fn ratio (
    secp_inst: &Secp256k1, 
    num: PublicKey, 
    den: PublicKey,
    ) -> PublicKey {

    let mut minus_den = den.clone();
    minus_den.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

    PublicKey::from_combination(&secp_inst, vec![&num, &minus_den]).unwrap()
}

//computes hash of arguments for Simplus signature and returns a scalar
pub fn hash_simple_tx (
    secp_inst: &Secp256k1,
    a1: PublicKey, a2: PublicKey, a3: PublicKey, a4: PublicKey, a5: PublicKey,
    a6: PublicKey, a7: PublicKey, a8: PublicKey,
    ) -> SecretKey {

    let mut hasher = Sha256::new();
    hasher.input(a1.serialize_vec(&secp_inst, true));
    hasher.input(a2.serialize_vec(&secp_inst, true));
    hasher.input(a3.serialize_vec(&secp_inst, true));
    hasher.input(a4.serialize_vec(&secp_inst, true));
    hasher.input(a5.serialize_vec(&secp_inst, true));
    hasher.input(a6.serialize_vec(&secp_inst, true));
    hasher.input(a7.serialize_vec(&secp_inst, true));
    hasher.input(a8.serialize_vec(&secp_inst, true));                  
    
    SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap()
}

//computes hash of arguments for Nummatus signature and returns a scalar
pub fn hash_special_tx (
    secp_inst: &Secp256k1,
    a1: PublicKey, a2: PublicKey, a3: PublicKey, a4: PublicKey, a5: PublicKey,
    a6: PublicKey, a7: PublicKey, a8: PublicKey, a9: PublicKey
    ) -> SecretKey {

    let mut hasher = Sha256::new();
    hasher.input(a1.serialize_vec(&secp_inst, true));
    hasher.input(a2.serialize_vec(&secp_inst, true));
    hasher.input(a3.serialize_vec(&secp_inst, true));
    hasher.input(a4.serialize_vec(&secp_inst, true));
    hasher.input(a5.serialize_vec(&secp_inst, true));
    hasher.input(a6.serialize_vec(&secp_inst, true));
    hasher.input(a7.serialize_vec(&secp_inst, true));
    hasher.input(a8.serialize_vec(&secp_inst, true));
    hasher.input(a9.serialize_vec(&secp_inst, true));    
    
    SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap()
}

//takes 3 Secretkeys a,b,x as arguments and returns a-b*x
pub fn a_minus_bx (secp_inst: &Secp256k1, a: SecretKey, b: SecretKey, x: SecretKey) -> SecretKey {
    let mut result = x;                                        // result = x
    result.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // result = -x
    result.mul_assign(&secp_inst, &b).unwrap();                // result = -b*x
    result.add_assign(&secp_inst, &a).unwrap();                // result = a - b*x

    result
}
