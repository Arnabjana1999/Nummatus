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
	c : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl SpecialVerifyPoK {

	pub fn new() -> SpecialVerifyPoK {
		SpecialVerifyPoK {
			c : ZERO_KEY,
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
		f_gen : PublicKey,
		h_gen : PublicKey,
		) -> SpecialVerifyPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut svpok = SpecialVerifyPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*g1 
	    let v1 = single_base_product(&secp_inst, pubkey_input.x.clone(), r1.clone());

	    //v2 = r1*y1    where y1 = g2-g1
	    let y1 = ratio(&secp_inst, pubkey_output.x.clone(), pubkey_input.x.clone());
	    let y2 = ratio(&secp_inst, pubkey_output.y.clone(), pubkey_input.y.clone());
	    let v2 = single_base_product(&secp_inst, y1.clone(), r1.clone());

	    //v3 = r1*z1    where z1 = c2-c
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v3 = single_base_product(&secp_inst, z1.clone(), r1.clone());

	    //v4 = r2*f
	    let v4 = single_base_product(&secp_inst, f_gen, r2.clone());
	    //v5 = r2*h
	    let v5 = single_base_product(&secp_inst, h_gen, r2.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								pubkey_input.x.clone(),
	    								y1.clone(),
	    								z1.clone(),
	    								f_gen,
	    								h_gen,
	    								pubkey_input.y.clone(),
	    								y2.clone(),
	    								z2.clone(),
	    								pubkey_output.x.clone(),
	    								pubkey_output.y.clone(),
	    								commitment_output.x.clone()
	    								);

	    // Calculation of c_1
	    svpok.c = hash_scalar;                                      // c_1 = H(S...r_3*G')

	    svpok.s1 = a_minus_bx(&secp_inst, r1.clone(), svpok.c.clone(), secret_key);
	    svpok.s2 = a_minus_bx(&secp_inst, r2.clone(), svpok.c.clone(), rand);

	    svpok
	}

	pub fn verify_pok (
		pubkey_input : QPublicKey,
		commitment_input : QPublicKey,
		pubkey_output : QPublicKey,
		commitment_output : QPublicKey,
		f_gen : PublicKey,
		h_gen : PublicKey,
		svpok : SpecialVerifyPoK,
		) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    //v1 = s1*g1 + c*h1
	    let v1 = double_base_product(&secp_inst, pubkey_input.x.clone(), pubkey_input.y.clone(), svpok.s1.clone(), svpok.c.clone());

	    //v2 = s1*y1 + c*y2        where y1 = g2-g1 and y2 = h2-h1
	    let y1 = ratio(&secp_inst, pubkey_output.x.clone(), pubkey_input.x.clone());
	    let y2 = ratio(&secp_inst, pubkey_output.y.clone(), pubkey_input.y.clone());
	    let v2 = double_base_product(&secp_inst, y1.clone(), y2.clone(), svpok.s1.clone(), svpok.c.clone());

	    //v3 = s1*z1 + c*z2        where z1 = c2-c and z2 = d2-d1
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v3 = double_base_product(&secp_inst, z1.clone(), z2.clone(), svpok.s1.clone(), svpok.c.clone());

	    //v4 = s2*f + c*g2
	    let v4 = double_base_product(&secp_inst, f_gen.clone(), pubkey_output.x.clone(), svpok.s2.clone(), svpok.c.clone());
	    //v5 = s2*h + c*c2
	    let v5 = double_base_product(&secp_inst, h_gen.clone(), commitment_output.x.clone(), svpok.s2.clone(), svpok.c.clone());

	    let hash_scalar = hash_simple_tx(&secp_inst,
	    								pubkey_input.x.clone(),
	    								y1.clone(),
	    								z1.clone(),
	    								f_gen,
	    								h_gen,
	    								pubkey_input.y.clone(),
	    								y2.clone(),
	    								z2.clone(),
	    								pubkey_output.x.clone(),
	    								pubkey_output.y.clone(),
	    								commitment_output.x.clone()
	    								);

	    svpok.c.clone() == hash_scalar    // comparing c from SpecialVerifyPoK and evaluation of the scalar-hash
	}
}

#[derive (Clone)]
pub struct QuisquisPRPoK {
	c : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
	s3 : SecretKey,
}

impl QuisquisPRPoK {
	pub fn new() -> QuisquisPRPoK {
		QuisquisPRPoK {
			c : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
			s3 : ZERO_KEY,
		}
	}

	pub fn create_pok (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		keyimage : PublicKey,
		secret_key : SecretKey,
		amount : u64,
		rand : SecretKey,
		f_gen : PublicKey,
		g_gen : PublicKey
		) -> QuisquisPRPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit); 

	    let mut rpok = QuisquisPRPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);
	    let r3 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r3*f
	    let v1 = single_base_product(&secp_inst, f_gen, r3.clone());
	    //v2 = r1*c2 + r2*g   
	    let v2 = double_base_product(&secp_inst, commitment.x.clone(), g_gen, r1.clone(), r2.clone());
	    //v3 = r2*g + r1*f
	    let v3 = double_base_product(&secp_inst, g_gen, f_gen, r2.clone(), r1.clone());

	    // Calculation of H(S || V_1 || V_2 || V_3 || r_3*h)
	    let mut hasher = Sha256::new();
	    hasher.input(g_gen.serialize_vec(&secp_inst, true));            	// Hash g
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash c2
	    hasher.input(f_gen.serialize_vec(&secp_inst, true));           		// Hash f
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash y
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash z
	    hasher.input(v1.serialize_vec(&secp_inst, true));                // Hash r1_g1
	    hasher.input(v2.serialize_vec(&secp_inst, true));             // Hash r1g2_r2g
	    hasher.input(v3.serialize_vec(&secp_inst, true));              // Hash r2g_r1h

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of c_1
	    rpok.c = hash_scalar;                                      // c_1 = H(S...r_3*G')

	    rpok.s1 = a_minus_bx(&secp_inst, r1.clone(), rpok.c.clone(), secret_key);
	    rpok.s2 = a_minus_bx(&secp_inst, r2.clone(), rpok.c.clone(), amount_to_key(&secp_inst, amount));
	    rpok.s3 = a_minus_bx(&secp_inst, r3.clone(), rpok.c.clone(), rand.clone());

	    rpok
	}

  	pub fn verify_pok (
  		pubkey : QPublicKey,
  		commitment : QPublicKey,
  		keyimage : PublicKey,
  		f_gen : PublicKey,
  		g_gen : PublicKey,
  		rpok : QuisquisPRPoK
  		) -> bool {

  		let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

  		//v1 = s3*f + c*x     where x = g2
	    let v1 = double_base_product(&secp_inst, f_gen.clone(), pubkey.x.clone(), rpok.s3.clone(), rpok.c.clone());
	    //v2 = s1*c2 + s2*g + c*y        where y = d2
	    let v2 = triple_base_product(&secp_inst, commitment.x.clone(), g_gen, commitment.y.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.c.clone());
	    //v3 = s2*g + s1*f + c*z         where z = I_i
	    let v3 = triple_base_product(&secp_inst, g_gen, f_gen, keyimage.clone(), rpok.s2.clone(), rpok.s1.clone(), rpok.c.clone());

	    // Calculation of H(S || V_1 || V_2 || V_3 || V_4)
	    let mut hasher = Sha256::new();
	    hasher.input(g_gen.serialize_vec(&secp_inst, true));            	// Hash g
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash c2
	    hasher.input(f_gen.serialize_vec(&secp_inst, true));           		// Hash f
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash y
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash z
	    hasher.input(v1.serialize_vec(&secp_inst, true));                   // Hash V_1
	    hasher.input(v2.serialize_vec(&secp_inst, true));                   // Hash V_2
	    hasher.input(v3.serialize_vec(&secp_inst, true));                   // Hash V_3

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    rpok.c.clone() == hash_scalar    // comparing c+c2 from QuisQuisPRPoK and evaluation of the scalar-hash
	}
}

#[derive (Clone)]
pub struct RepresentationPoK {
	c : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
}

impl RepresentationPoK {
	pub fn new() -> RepresentationPoK {
		RepresentationPoK {
			c : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
		}
	}

	pub fn create_pok (
		keyimage : PublicKey,   //I_i   z
		secret_key : SecretKey,
		amount : u64,
		value_gen : PublicKey,   //g
		secret_gen : PublicKey,  //h
		) -> RepresentationPoK {

		let mut rng = thread_rng();
		let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

		let mut rep_pok = RepresentationPoK::new();
    	let r1 = SecretKey::new(&secp_inst, &mut rng);
    	let r2 = SecretKey::new(&secp_inst, &mut rng);

    	//Calculation of r2*g + r1*h
    	let mut r2_g = value_gen.clone();
    	r2_g.mul_assign(&secp_inst, &r2).unwrap();
    	let mut r1_h = secret_gen.clone();
    	r1_h.mul_assign(&secp_inst, &r1).unwrap();
    	let r2g_r1h = PublicKey::from_combination(&secp_inst, vec![&r2_g, &r1_h]).unwrap();

    	// Calculation of H(S || r2*g + r1*h)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));     // Hash g
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));    // Hash h
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));      // Hash \sum I_i
	    hasher.input(r2g_r1h.serialize_vec(&secp_inst, true));       // Hash r2*g + r1*h

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of c
	    rep_pok.c = hash_scalar;                                       // c = H(S...V_3)

	    // Calculation of s_1
	    rep_pok.s1 = secret_key;                                       // s_1 = alpha
	    rep_pok.s1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_1 = -alpha
	    rep_pok.s1.mul_assign(&secp_inst, &rep_pok.c).unwrap();        // s_1 = -c*alpha
	    rep_pok.s1.add_assign(&secp_inst, &r1).unwrap();               // s_1 = r_1 - c*alpha

	    // Calculation of s_2
	    rep_pok.s2 = amount_to_key(&secp_inst, amount);    // s_2 = beta
	    rep_pok.s2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_2 = -beta
	    rep_pok.s2.mul_assign(&secp_inst, &rep_pok.c).unwrap();         // s_2 = -c*beta
	    rep_pok.s2.add_assign(&secp_inst, &r2).unwrap();               // s_2 = r_2 - c*beta

	    rep_pok
	}

	  pub fn verify_pok (
	    keyimage: &PublicKey,
	    secret_gen: &PublicKey,     // h
	    value_gen: &PublicKey,      // g
	    rep_pok: &RepresentationPoK,
	  ) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    // Calculation of V = s2*g + s1*h + c*x    where x = \sum I_i
	    let mut s2_g = value_gen.clone();
	    s2_g.mul_assign(&secp_inst, &rep_pok.s2).unwrap();
	    let mut s1_h = secret_gen.clone();
	    s1_h.mul_assign(&secp_inst, &rep_pok.s1).unwrap();
	    let mut c_x = keyimage.clone();
	    c_x.mul_assign(&secp_inst, &rep_pok.c).unwrap();
	    let v = PublicKey::from_combination(&secp_inst, vec![&s2_g, &s1_h, &c_x]).unwrap();

	    // Calculation of H(S || V)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));     // Hash g
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));    // Hash h
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));      // Hash \sum I_i
	    hasher.input(v.serialize_vec(&secp_inst, true));           	 // Hash V

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    rep_pok.c == hash_scalar
	  }
}