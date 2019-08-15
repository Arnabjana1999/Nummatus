use digest::Digest;
use sha2::Sha256;
use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::MINUS_ONE_KEY;
use crate::misc::amount_to_key;
use crate::misc::single_base_product;
use crate::misc::double_base_product;
use crate::misc::triple_base_product;
use crate::misc::ratio;
use crate::misc::hash_special_tx;
use crate::misc::a_minus_bx;

#[derive (Clone)]
pub struct NummatusPoK {
	e1 : SecretKey,
	e2 : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
	s3 : SecretKey,
}

impl NummatusPoK {

	pub fn new() -> NummatusPoK {
		NummatusPoK {
			e1 : ZERO_KEY,
			e2 : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
			s3 : ZERO_KEY,
		}
	}

	pub fn create_pok_from_decoy (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		keyimage : PublicKey,
		gamma : SecretKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		) -> NummatusPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = NummatusPoK::new();
	    let r3 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.e1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = s1*a + e1*b    
	    let v1 = double_base_product(&secp_inst, pubkey.x.clone(), pubkey.y.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v2 = s1*g + e1*q     
	    let v2 = double_base_product(&secp_inst, g_gen.clone(), keyimage.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v3 = s1*c + s2*h + e1*(d-p)  
	    let d_minus_p = ratio(&secp_inst, commitment.y.clone(), pederson.clone());
	    let v3 = triple_base_product(&secp_inst, commitment.x.clone(), h_gen.clone(), d_minus_p.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.e1.clone());

	    //v4 = r3*h
	    let v4 = single_base_product(&secp_inst, h_gen.clone(), r3.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								g_gen,
	    								h_gen,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								keyimage.clone(),          //q
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								v4.clone()
	    								);

	    // Calculation of -e_1
	    let mut minus_e1 = rpok.e1.clone();
	    minus_e1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_2
	    rpok.e2 = hash_scalar;                                      // e_2 = H(S...r_3*h)
	    rpok.e2.add_assign(&secp_inst, &minus_e1).unwrap();         // e_2 = H(S...r_3*h) - e_1

	    rpok.s3 = a_minus_bx(&secp_inst, r3.clone(), rpok.e2.clone(), gamma);
	    rpok
	}

	pub fn create_pok_from_representation (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		keyimage : PublicKey,
		alpha : SecretKey,
		beta : SecretKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		) -> NummatusPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = NummatusPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.e2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s3 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*a
	    let v1 = single_base_product(&secp_inst, pubkey.x.clone(), r1.clone());

	    //v2 = r1*g
	    let v2 = single_base_product(&secp_inst, g_gen.clone(), r1.clone());

	    //v3 = r1*c + r2*h
	    let v3 = double_base_product(&secp_inst, commitment.x.clone(), h_gen.clone(), r1.clone(), r2.clone());

	    //v4 = s3*h + e2*p
	    let v4 = double_base_product(&secp_inst, h_gen.clone(), pederson.clone(), rpok.s3.clone(), rpok.e2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								g_gen,
	    								h_gen,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								keyimage.clone(),          //q
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								v4.clone(),
	    								);

	    // Calculation of -e_2
	    let mut minus_e2 = rpok.e2.clone();
	    minus_e2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_1
	    rpok.e1 = hash_scalar;                                      // e_1 = H(S...V_4)
	    rpok.e1.add_assign(&secp_inst, &minus_e2).unwrap();         // e_1 = H(S...V_4) - e_2

	    rpok.s1 = a_minus_bx(&secp_inst, r1.clone(), rpok.e1.clone(), alpha);
	    rpok.s2 = a_minus_bx(&secp_inst, r2.clone(), rpok.e1.clone(), beta);

	    rpok
	}

	pub fn verify_pok (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		keyimage : PublicKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		rpok : NummatusPoK,
		) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = s1*a + e1*b    
	    let v1 = double_base_product(&secp_inst, pubkey.x.clone(), pubkey.y.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v2 = s1*g + e1*q     
	    let v2 = double_base_product(&secp_inst, g_gen.clone(), keyimage.clone(), rpok.s1.clone(), rpok.e1.clone());

	    //v3 = s1*c + s2*h + e1*(d-p)  
	    let d_minus_p = ratio(&secp_inst, commitment.y.clone(), pederson.clone());
	    let v3 = triple_base_product(&secp_inst, commitment.x.clone(), h_gen.clone(), d_minus_p.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.e1.clone());

	    //v4 = s3*h + e2*p
	    let v4 = double_base_product(&secp_inst, h_gen.clone(), pederson.clone(), rpok.s3.clone(), rpok.e2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								g_gen,
	    								h_gen,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								keyimage.clone(),          //q
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								v4.clone()
	    								);

	    let mut e_sum = rpok.e1.clone();
	    e_sum.add_assign(&secp_inst, &rpok.e2).unwrap();

	    e_sum == hash_scalar    // comparing e1+e2 from NummatusPoK and evaluation of the scalar-hash
	}
}