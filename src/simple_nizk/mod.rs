use digest::Digest;
use sha2::Sha256;
use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::amount_to_key;
use crate::misc::single_base_product;
use crate::misc::double_base_product;
use crate::misc::triple_base_product;
use crate::misc::ratio;
use crate::misc::hash_simple_tx;
use crate::misc::a_minus_bx;

#[derive (Clone)]
pub struct SimplePoK {
	e : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl SimplePoK {

	pub fn new() -> SimplePoK {
		SimplePoK {
			e : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
		}
	}

	pub fn create_pok_from_representation (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		alpha : SecretKey,
		beta : SecretKey,
		h_gen : PublicKey,
		) -> SimplePoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = SimplePoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*a
	    let v1 = single_base_product(&secp_inst, pubkey.x.clone(), r1.clone());

	    //v2 = r1*c + r2*h
	    let v2 = double_base_product(&secp_inst, commitment.x.clone(), h_gen.clone(), r1.clone(), r2.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								h_gen,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								v1.clone(),
	    								v2.clone()
	    								);

	    // Calculation of e_1
	    rpok.e = hash_scalar;                                      // e_1 = H(S...V_2)

	    rpok.s1 = a_minus_bx(&secp_inst, r1.clone(), rpok.e.clone(), alpha);
	    rpok.s2 = a_minus_bx(&secp_inst, r2.clone(), rpok.e.clone(), beta);

	    rpok
	}

	pub fn verify_pok (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		h_gen : PublicKey,
		rpok : SimplePoK,
		) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = s1*a + e1*b    
	    let v1 = double_base_product(&secp_inst, pubkey.x.clone(), pubkey.y.clone(), rpok.s1.clone(), rpok.e.clone());

	    //v2 = s1*c + s2*h + e1*(d-p)  
	    let d_minus_p = ratio(&secp_inst, commitment.y.clone(), pederson.clone());
	    let v2 = triple_base_product(&secp_inst, commitment.x.clone(), h_gen.clone(), d_minus_p.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.e.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								h_gen,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								v1.clone(),
	    								v2.clone()
	    								);

	    let mut e = rpok.e.clone();

	    e == hash_scalar    // comparing e from SimplePoK and evaluation of the scalar-hash
	}
}