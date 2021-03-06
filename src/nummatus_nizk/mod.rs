use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::MINUS_ONE_KEY;
use crate::misc::single_base_product;
use crate::misc::double_base_product;
use crate::misc::ratio;
use crate::misc::hash_special_tx;
use crate::misc::a_minus_bx;

#[derive (Clone)]
pub struct NummatusPoK {
	e1 : SecretKey,
	e2 : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl NummatusPoK {

	pub fn new() -> NummatusPoK {
		NummatusPoK {
			e1 : ZERO_KEY,
			e2 : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
		}
	}

	pub fn create_pok_from_decoy (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pedersen_com : PublicKey,
		beta : SecretKey,
		h_j : PublicKey,
		) -> NummatusPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = NummatusPoK::new();
	    let r2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.e1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s1 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = a^s1 + b^e1    
	    let v1 = double_base_product(&secp_inst, pubkey.x.clone(), pubkey.y.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v2 = (h*c^-1)^s1 * (p*d^-1)^e1  
	    let p_minus_d = ratio(&secp_inst, pedersen_com.clone(), commitment.y.clone());
	    let h_minus_c = ratio(&secp_inst, h_j.clone(), commitment.x.clone());
	    let v2 = double_base_product(&secp_inst, h_minus_c.clone(), p_minus_d.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v3 = h^r2
	    let v3 = single_base_product(&secp_inst, h_j.clone(), r2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								h_j,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pedersen_com.clone(),          //p
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone()
	    								);

	    // Calculation of -e_1
	    let mut minus_e1 = rpok.e1.clone();
	    minus_e1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_2
	    rpok.e2 = hash_scalar;                                      // e_2 = H(h_j, a, b, c, d, p, v1, v2, v3)
	    rpok.e2.add_assign(&secp_inst, &minus_e1).unwrap();         // e_2 = H(h_j, a, b, c, d, p, v1, v2, v3) - e_1

	    rpok.s2 = a_minus_bx(&secp_inst, r2.clone(), rpok.e2.clone(), beta);
	    rpok
	}

	pub fn create_pok_from_representation (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pedersen_com : PublicKey,
		alpha : SecretKey,
		h_j : PublicKey,
		) -> NummatusPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = NummatusPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.e2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = a^r1
	    let v1 = single_base_product(&secp_inst, pubkey.x.clone(), r1.clone());

	    //v2 = (h*c^-1)^r1
	    let h_minus_c = ratio(&secp_inst, h_j.clone(), commitment.x.clone());
	    let v2 = single_base_product(&secp_inst, h_minus_c.clone(), r1.clone());

	    //v3 = h^s2 * p^e2
	    let v3 = double_base_product(&secp_inst, h_j.clone(), pedersen_com.clone(), rpok.s2.clone(), rpok.e2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								h_j,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pedersen_com.clone(),          //p
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								);

	    // Calculation of -e_2
	    let mut minus_e2 = rpok.e2.clone();
	    minus_e2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_1
	    rpok.e1 = hash_scalar;                                      // e_1 = H(h_j, a, b, c, d, p, v1, v2, v3)
	    rpok.e1.add_assign(&secp_inst, &minus_e2).unwrap();         // e_1 = H(h_j, a, b, c, d, p, v1, v2, v3) - e_2

	    rpok.s1 = a_minus_bx(&secp_inst, r1.clone(), rpok.e1.clone(), alpha);
	    rpok
	}

	pub fn verify_pok (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pedersen_com : PublicKey,
		h_j : PublicKey,
		rpok : NummatusPoK,
		) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = a^s1 * b^e1    
	    let v1 = double_base_product(&secp_inst, pubkey.x.clone(), pubkey.y.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v2 = (h*c^-1)^s1 * (p*d^-1)^e1  
	    let p_minus_d = ratio(&secp_inst, pedersen_com.clone(), commitment.y.clone());
	    let h_minus_c = ratio(&secp_inst, h_j.clone(), commitment.x.clone());
	    let v2 = double_base_product(&secp_inst, h_minus_c.clone(), p_minus_d.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v3 = h^s2 * p^e2
	    let v3 = double_base_product(&secp_inst, h_j.clone(), pedersen_com.clone(), rpok.s2.clone(), rpok.e2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								h_j,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pedersen_com.clone(),          //p
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								);

	    let mut e_sum = rpok.e1.clone();
	    e_sum.add_assign(&secp_inst, &rpok.e2).unwrap();

	    e_sum == hash_scalar    // comparing e1+e2 from NummatusPoK and evaluation of the scalar-hash
	}
}