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
use crate::misc::hash_simple_tx;
use crate::misc::a_minus_bx;

#[derive (Clone)]
pub struct SpecialVerifyPoK {
	e : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl SpecialVerifyPoK {

	pub fn new() -> SpecialVerifyPoK {
		SpecialVerifyPoK {
			e : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
		}
	}

	pub fn create_pok (
		pubkey_input : QPublicKey,
		commitment_input : QPublicKey,
		pubkey_output : QPublicKey,
		commitment_output : QPublicKey,
		secret_key : SecretKey,
		rand : SecretKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		f_gen : PublicKey,
		) -> SpecialVerifyPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut svpok = SpecialVerifyPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*g1 
	    let v1 = single_base_product(&secp_inst, pubkey_input.x.clone(), r1.clone());

	    //v2 = r1*z1    where z1 = c2-c1
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v2 = single_base_product(&secp_inst, z1.clone(), r1.clone());

	    //v3 = r2*h
	    let v3 = single_base_product(&secp_inst, h_gen, r2.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								g_gen.clone(),
	    								h_gen.clone(),
	    								f_gen.clone(),
	    								pubkey_input.x.clone(),
	    								pubkey_input.y.clone(),
	    								commitment_input.x.clone(),
	    								commitment_input.y.clone(),
	    								commitment_output.x.clone(),
	    								commitment_output.y.clone(),
	    								z1.clone(),
	    								z2.clone(),
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone()
	    								);

	    // Calculation of e
	    svpok.e = hash_scalar;                                

	    svpok.s1 = a_minus_bx(&secp_inst, r1.clone(), svpok.e.clone(), secret_key);
	    svpok.s2 = a_minus_bx(&secp_inst, r2.clone(), svpok.e.clone(), rand);

	    svpok
	}

	pub fn verify_pok (
		pubkey_input : QPublicKey,
		commitment_input : QPublicKey,
		pubkey_output : QPublicKey,
		commitment_output : QPublicKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		f_gen : PublicKey,
		svpok : SpecialVerifyPoK,
		) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = s1*g1 + e*h1
	    let v1 = double_base_product(&secp_inst, pubkey_input.x.clone(), pubkey_input.y.clone(), svpok.s1.clone(), svpok.e.clone());

	    //v2 = s1*z1 + e*z2        where z1 = c2-c1 and z2 = d2-d1
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v2 = double_base_product(&secp_inst, z1.clone(), z2.clone(), svpok.s1.clone(), svpok.e.clone());

	    //v3 = s2*h + e*c2
	    let v3 = double_base_product(&secp_inst, h_gen.clone(), commitment_output.x.clone(), svpok.s2.clone(), svpok.e.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								g_gen.clone(),
	    								h_gen.clone(),
	    								f_gen.clone(),
	    								pubkey_input.x.clone(),
	    								pubkey_input.y.clone(),
	    								commitment_input.x.clone(),
	    								commitment_input.y.clone(),
	    								commitment_output.x.clone(),
	    								commitment_output.y.clone(),
	    								z1.clone(),
	    								z2.clone(),
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone()
	    								);

	    svpok.e.clone() == hash_scalar    // comparing c from SpecialVerifyPoK and evaluation of the scalar-hash
	}
}

#[derive (Clone)]
pub struct QuisquisPRPoK {
	e : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl QuisquisPRPoK {
	pub fn new() -> QuisquisPRPoK {
		QuisquisPRPoK {
			e : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
		}
	}

	pub fn create_pok (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		keyimage : PublicKey,
		secret_key : SecretKey,
		amount : u64,
		g_gen : PublicKey,
		h_gen : PublicKey,
		f_gen : PublicKey
		) -> QuisquisPRPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit); 

	    let mut rpok = QuisquisPRPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*c2 + r2*g   
	    let v1 = double_base_product(&secp_inst, commitment.x.clone(), g_gen, r1.clone(), r2.clone());
	    //v2 = r2*g + r1*f
	    let v2 = double_base_product(&secp_inst, g_gen, f_gen, r2.clone(), r1.clone());

	    // Calculation of H(S || V_1 || V_2)
	    let mut hasher = Sha256::new();
	    hasher.input(g_gen.serialize_vec(&secp_inst, true));            	// Hash g
	    hasher.input(h_gen.serialize_vec(&secp_inst, true));                // Hash h
	    hasher.input(f_gen.serialize_vec(&secp_inst, true));           		// Hash f
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash g2
	    hasher.input(pubkey.y.serialize_vec(&secp_inst, true));             // Hash h2
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash c2
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash d2
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(v1.serialize_vec(&secp_inst, true));                   // Hash r1g2_r2g
	    hasher.input(v2.serialize_vec(&secp_inst, true));                   // Hash r2g_r1h

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of c_1
	    rpok.e = hash_scalar;                                   

	    rpok.s1 = a_minus_bx(&secp_inst, r1.clone(), rpok.e.clone(), secret_key);
	    rpok.s2 = a_minus_bx(&secp_inst, r2.clone(), rpok.e.clone(), amount_to_key(&secp_inst, amount));

	    rpok
	}

  	pub fn verify_pok (
  		pubkey : QPublicKey,
  		commitment : QPublicKey,
  		keyimage : PublicKey,
  		g_gen : PublicKey,
  		h_gen : PublicKey,
  		f_gen : PublicKey,
  		rpok : QuisquisPRPoK
  		) -> bool {

  		let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = s1*c2 + s2*g + c*y        where y = d2
	    let v1 = triple_base_product(&secp_inst, commitment.x.clone(), g_gen, commitment.y.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.e.clone());
	    //v2 = s2*g + s1*f + c*z         where z = I_i
	    let v2 = triple_base_product(&secp_inst, g_gen, f_gen, keyimage.clone(), rpok.s2.clone(), rpok.s1.clone(), rpok.e.clone());

	    // Calculation of H(S || V_1 || V_2)
	    let mut hasher = Sha256::new();
	    hasher.input(g_gen.serialize_vec(&secp_inst, true));            	// Hash g
	    hasher.input(h_gen.serialize_vec(&secp_inst, true));                // Hash h
	    hasher.input(f_gen.serialize_vec(&secp_inst, true));           		// Hash f
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash g2
	    hasher.input(pubkey.y.serialize_vec(&secp_inst, true));             // Hash h2
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash c2
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash d2
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(v1.serialize_vec(&secp_inst, true));                   // Hash V_1
	    hasher.input(v2.serialize_vec(&secp_inst, true));                   // Hash V_2

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    rpok.e.clone() == hash_scalar    // comparing e from QuisQuisPRPoK and evaluation of the scalar-hash
	}
}

#[derive (Clone)]
pub struct RepresentationPoK {
	e : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl RepresentationPoK {
	pub fn new() -> RepresentationPoK {
		RepresentationPoK {
			e : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
		}
	}

	pub fn create_pok (
		keyimage : PublicKey,   //\sum I_i
		secret_key : SecretKey,
		amount : u64,
		g_gen : PublicKey,   //g
		f_gen : PublicKey,   //f
		) -> RepresentationPoK {

		let mut rng = thread_rng();
		let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

		let mut rep_pok = RepresentationPoK::new();
    	let r1 = SecretKey::new(&secp_inst, &mut rng);
    	let r2 = SecretKey::new(&secp_inst, &mut rng);

    	//Calculation of r2*g + r1*f
    	let mut r2_g = g_gen.clone();
    	r2_g.mul_assign(&secp_inst, &r2).unwrap();
    	let mut r1_f = f_gen.clone();
    	r1_f.mul_assign(&secp_inst, &r1).unwrap();
    	let r2g_r1h = PublicKey::from_combination(&secp_inst, vec![&r2_g, &r1_f]).unwrap();

    	// Calculation of H(S || r2*g + r1*f)
	    let mut hasher = Sha256::new();
	    hasher.input(g_gen.serialize_vec(&secp_inst, true));         // Hash g
	    hasher.input(f_gen.serialize_vec(&secp_inst, true));         // Hash f
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));      // Hash \sum I_i
	    hasher.input(r2g_r1h.serialize_vec(&secp_inst, true));       // Hash r2*g + r1*f

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of e
	    rep_pok.e = hash_scalar; 

	    rep_pok.s1 = a_minus_bx(&secp_inst, r1.clone(), rep_pok.e.clone(), secret_key);
	    rep_pok.s2 = a_minus_bx(&secp_inst, r2.clone(), rep_pok.e.clone(), amount_to_key(&secp_inst, amount));
	  
	    rep_pok
	}

	  pub fn verify_pok (
	    keyimage: &PublicKey,
	    f_gen: &PublicKey,      // f
	    g_gen: &PublicKey,      // g
	    rep_pok: &RepresentationPoK,
	  ) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    // Calculation of V = s2*g + s1*f + e*x    where x = \sum I_i
	    let mut s2_g = g_gen.clone();
	    s2_g.mul_assign(&secp_inst, &rep_pok.s2).unwrap();
	    let mut s1_f = f_gen.clone();
	    s1_f.mul_assign(&secp_inst, &rep_pok.s1).unwrap();
	    let mut e_x = keyimage.clone();
	    e_x.mul_assign(&secp_inst, &rep_pok.e).unwrap();
	    let v = PublicKey::from_combination(&secp_inst, vec![&s2_g, &s1_f, &e_x]).unwrap();

	    // Calculation of H(S || V)
	    let mut hasher = Sha256::new();
	    hasher.input(g_gen.serialize_vec(&secp_inst, true));         // Hash g
	    hasher.input(f_gen.serialize_vec(&secp_inst, true));         // Hash f
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));      // Hash \sum I_i
	    hasher.input(v.serialize_vec(&secp_inst, true));           	 // Hash V

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    rep_pok.e == hash_scalar
	  }
}