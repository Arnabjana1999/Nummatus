use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::single_base_product;
use crate::misc::double_base_product;
use crate::misc::ratio;
use crate::misc::hash_simple_tx;
use crate::misc::a_minus_bx;

#[derive (Clone)]
pub struct SimplePoK {
	e : SecretKey,
	s : SecretKey,
}

impl SimplePoK {

	pub fn new() -> SimplePoK {
		SimplePoK {
			e : ZERO_KEY,
			s : ZERO_KEY,
		}
	}

	pub fn create_pok_from_representation (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		alpha : SecretKey,
		h_j : PublicKey,
		) -> SimplePoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = SimplePoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = a^r1
	    let v1 = single_base_product(&secp_inst, pubkey.x.clone(), r1.clone());

	    //v2 = (h*c^-1)^r1
	    let h_minus_c = ratio(&secp_inst, h_j.clone(), commitment.x.clone());
	    let v2 = single_base_product(&secp_inst, h_minus_c.clone(), r1.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								h_j,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								v1.clone(),
	    								v2.clone()
	    								);

	    // Calculation of e_1
	    rpok.e = hash_scalar;                                      // e_1 = H(h_j, a, b, c, d, p, v1, v2)

	    rpok.s = a_minus_bx(&secp_inst, r1.clone(), rpok.e.clone(), alpha);

	    rpok
	}

	pub fn verify_pok (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		pederson : PublicKey,
		h_j : PublicKey,
		rpok : SimplePoK,
		) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = a^s * b^e    
	    let v1 = double_base_product(&secp_inst, pubkey.x.clone(), pubkey.y.clone(), rpok.s.clone(), rpok.e.clone());

	    //v2 = c^s * h^s2 * (d*p^-1)^e1  
	    let p_minus_d = ratio(&secp_inst, pederson.clone(), commitment.y.clone());
	    let h_minus_c = ratio(&secp_inst, h_j.clone(), commitment.x.clone());
	    let v2 = double_base_product(&secp_inst, h_minus_c.clone(), p_minus_d.clone(), rpok.s.clone(), rpok.e.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								h_j,
	    								pubkey.x.clone(),          //a
	    								pubkey.y.clone(),          //b
	    								commitment.x.clone(),      //c
	    								commitment.y.clone(),      //d
	    								pederson.clone(),          //p
	    								v1.clone(),
	    								v2.clone()
	    								);

	    let e = rpok.e.clone();

	    e == hash_scalar    // comparing e from SimplePoK and evaluation of the scalar-hash
	}
}