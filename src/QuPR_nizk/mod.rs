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
pub struct SpecialVerifyPoK {
	e1 : SecretKey,
	e2 : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
	s3 : SecretKey,
	s4 : SecretKey,
}

impl SpecialVerifyPoK {

	pub fn new() -> SpecialVerifyPoK {
		SpecialVerifyPoK {
			e1 : ZERO_KEY,
			e2 : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
			s3 : ZERO_KEY,
			s4 : ZERO_KEY,
		}
	}

	pub fn create_pok_from_decoy (
		pubkey_input : QPublicKey,
		commitment_input : QPublicKey,
		pubkey_output : QPublicKey,
		commitment_output : QPublicKey,
		rand1 : SecretKey,
		rand2 : SecretKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		f_gen : PublicKey,
		) -> SpecialVerifyPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut svpok = SpecialVerifyPoK::new();
	    let r3 = SecretKey::new(&secp_inst, &mut rng);
	    let r4 = SecretKey::new(&secp_inst, &mut rng);
	    svpok.e1 = SecretKey::new(&secp_inst, &mut rng);
	    svpok.s1 = SecretKey::new(&secp_inst, &mut rng);
	    svpok.s2 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = s1*g1 + e1*x     where x = h1
	    let v1 = double_base_product(&secp_inst, pubkey_input.x.clone(), pubkey_input.y.clone(), svpok.s1.clone(), svpok.e1.clone());

	    //v2 = s1*y1 + e1*y2        where y1 = g2-g1 and y2 = h2-h1
	    let y1 = ratio(&secp_inst, pubkey_output.x.clone(), pubkey_input.x.clone());
	    let y2 = ratio(&secp_inst, pubkey_output.y.clone(), pubkey_input.y.clone());
	    let v2 = double_base_product(&secp_inst, y1.clone(), y2.clone(), svpok.s1.clone(), svpok.e1.clone());

	    //v3 = s1*z1 + e1*z2        where z1 = e2-e1 and z2 = d2-d1
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v3 = double_base_product(&secp_inst, z1.clone(), z2.clone(), svpok.s1.clone(), svpok.e1.clone());

	    //v4 = s2*f + e1*a     where a = g2
	    let v4 = double_base_product(&secp_inst, f_gen, pubkey_output.x.clone(), svpok.s2.clone(), svpok.e1.clone());
	    //v5 = s2*h + e1*b     where b = e2
	    let v5 = double_base_product(&secp_inst, h_gen, commitment_output.x.clone(), svpok.s2.clone(), svpok.e1.clone());

	    //v6 = r3*g1
	    let v6 = single_base_product(&secp_inst, pubkey_input.x.clone(), r3.clone());
	    //v7 = r3*h1
	    let v7 = single_base_product(&secp_inst, pubkey_input.y.clone(), r3.clone());
	    //v8 = r4*g1
	    let v8 = single_base_product(&secp_inst, pubkey_input.x.clone(), r4.clone());
	    //v9 = r4*h1
	    let v9 = single_base_product(&secp_inst, pubkey_input.y.clone(), r4.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								g_gen,
	    								f_gen,
	    								h_gen,
	    								pubkey_input.x.clone(),          //g1
	    								pubkey_input.y.clone(),          //h1
	    								commitment_input.x.clone(),      //c1
	    								commitment_input.y.clone(),      //d1
	    								pubkey_output.x.clone(),         //g2
	    								pubkey_output.y.clone(),         //h2
	    								commitment_output.x.clone(),     //c2
	    								commitment_output.y.clone(),     //d2
	    								y1.clone(),                      //g_div
	    								y2.clone(),                      //h_div
	    								z1.clone(),                      //c_div
	    								z2.clone(),                      //d_div
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								v4.clone(),
	    								v5.clone(),
	    								v6.clone(),
	    								v7.clone(),
	    								v8.clone(),
	    								v9.clone()
	    								);

	    // Calculation of -e_1
	    let mut minus_e1 = svpok.e1.clone();
	    minus_e1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_2
	    svpok.e2 = hash_scalar;                                      // e_2 = H(S...r_3*G')
	    svpok.e2.add_assign(&secp_inst, &minus_e1).unwrap();         // e_2 = H(S...r_3*G') - e_1

	    svpok.s3 = a_minus_bx(&secp_inst, r3.clone(), svpok.e2.clone(), rand1);
	    svpok.s4 = a_minus_bx(&secp_inst, r4.clone(), svpok.e2.clone(), rand2);

	    svpok
	}

	pub fn create_pok_from_representation (
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
	    svpok.e2 = SecretKey::new(&secp_inst, &mut rng);
	    svpok.s3 = SecretKey::new(&secp_inst, &mut rng);
	    svpok.s4 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*g1 
	    let v1 = single_base_product(&secp_inst, pubkey_input.x.clone(), r1.clone());

	    //v2 = r1*y1    where y1 = g2-g1
	    let y1 = ratio(&secp_inst, pubkey_output.x.clone(), pubkey_input.x.clone());
	    let y2 = ratio(&secp_inst, pubkey_output.y.clone(), pubkey_input.y.clone());
	    let v2 = single_base_product(&secp_inst, y1.clone(), r1.clone());

	    //v3 = r1*z1    where z1 = e2-e1
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v3 = single_base_product(&secp_inst, z1.clone(), r1.clone());

	    //v4 = r2*f
	    let v4 = single_base_product(&secp_inst, f_gen, r2.clone());
	    //v5 = r2*h
	    let v5 = single_base_product(&secp_inst, h_gen, r2.clone());

	    //v6 = s3*g1 + e2*g2
	    let v6 = double_base_product(&secp_inst, pubkey_input.x.clone(), pubkey_output.x.clone(), svpok.s3.clone(), svpok.e2.clone());
	    //v7 = s3*h1 + e2*h2
	    let v7 = double_base_product(&secp_inst, pubkey_input.y.clone(), pubkey_output.y.clone(), svpok.s3.clone(), svpok.e2.clone());
	    //v8 = s4*g1 + e2*z1
	    let v8 = double_base_product(&secp_inst, pubkey_input.x.clone(), z1.clone(), svpok.s4.clone(), svpok.e2.clone());
	    //v9 = s4*h1 + e2*z2
	    let v9 = double_base_product(&secp_inst, pubkey_input.y.clone(), z2.clone(), svpok.s4.clone(), svpok.e2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								g_gen,
	    								f_gen,
	    								h_gen,
	    								pubkey_input.x.clone(),          //g1
	    								pubkey_input.y.clone(),          //h1
	    								commitment_input.x.clone(),      //c1
	    								commitment_input.y.clone(),      //d1
	    								pubkey_output.x.clone(),         //g2
	    								pubkey_output.y.clone(),         //h2
	    								commitment_output.x.clone(),     //c2
	    								commitment_output.y.clone(),     //d2
	    								y1.clone(),                      //g_div
	    								y2.clone(),                      //h_div
	    								z1.clone(),                      //c_div
	    								z2.clone(),                      //d_div
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								v4.clone(),
	    								v5.clone(),
	    								v6.clone(),
	    								v7.clone(),
	    								v8.clone(),
	    								v9.clone()
	    								);

	    // Calculation of -e_2
	    let mut minus_e2 = svpok.e2.clone();
	    minus_e2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_1
	    svpok.e1 = hash_scalar;                                      // e_1 = H(S...r_3*G')
	    svpok.e1.add_assign(&secp_inst, &minus_e2).unwrap();         // e_1 = H(S...r_3*G') - e_2

	    svpok.s1 = a_minus_bx(&secp_inst, r1.clone(), svpok.e1.clone(), secret_key);
	    svpok.s2 = a_minus_bx(&secp_inst, r2.clone(), svpok.e1.clone(), rand);

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

	    //v1 = s1*g1 + e1*h1
	    let v1 = double_base_product(&secp_inst, pubkey_input.x.clone(), pubkey_input.y.clone(), svpok.s1.clone(), svpok.e1.clone());

	    //v2 = s1*y1 + e1*y2        where y1 = g2-g1 and y2 = h2-h1
	    let y1 = ratio(&secp_inst, pubkey_output.x.clone(), pubkey_input.x.clone());
	    let y2 = ratio(&secp_inst, pubkey_output.y.clone(), pubkey_input.y.clone());
	    let v2 = double_base_product(&secp_inst, y1.clone(), y2.clone(), svpok.s1.clone(), svpok.e1.clone());

	    //v3 = s1*z1 + e1*z2        where z1 = e2-e1 and z2 = d2-d1
	    let z1 = ratio(&secp_inst, commitment_output.x.clone(), commitment_input.x.clone());
	    let z2 = ratio(&secp_inst, commitment_output.y.clone(), commitment_input.y.clone());
	    let v3 = double_base_product(&secp_inst, z1.clone(), z2.clone(), svpok.s1.clone(), svpok.e1.clone());

	    //v4 = s2*f + e1*g2
	    let v4 = double_base_product(&secp_inst, f_gen.clone(), pubkey_output.x.clone(), svpok.s2.clone(), svpok.e1.clone());
	    //v5 = s2*h + e1*e2
	    let v5 = double_base_product(&secp_inst, h_gen.clone(), commitment_output.x.clone(), svpok.s2.clone(), svpok.e1.clone());

	    //v6 = s3*g1 + e2*g2
	    let v6 = double_base_product(&secp_inst, pubkey_input.x.clone(), pubkey_output.x.clone(), svpok.s3.clone(), svpok.e2.clone());
	    //v7 = s3*h1 + e2*h2
	    let v7 = double_base_product(&secp_inst, pubkey_input.y.clone(), pubkey_output.y.clone(), svpok.s3.clone(), svpok.e2.clone());
	    //v8 = s4*g1 + e2*z1
	    let v8 = double_base_product(&secp_inst, pubkey_input.x.clone(), z1.clone(), svpok.s4.clone(), svpok.e2.clone());
	    //v9 = s4*h1 + e2*z2
	    let v9 = double_base_product(&secp_inst, pubkey_input.y.clone(), z2.clone(), svpok.s4.clone(), svpok.e2.clone());

	    let hash_scalar = hash_special_tx(&secp_inst,
	    								g_gen,
	    								f_gen,
	    								h_gen,
	    								pubkey_input.x.clone(),          //g1
	    								pubkey_input.y.clone(),          //h1
	    								commitment_input.x.clone(),      //c1
	    								commitment_input.y.clone(),      //d1
	    								pubkey_output.x.clone(),         //g2
	    								pubkey_output.y.clone(),         //h2
	    								commitment_output.x.clone(),     //c2
	    								commitment_output.y.clone(),     //d2
	    								y1.clone(),                      //g_div
	    								y2.clone(),                      //h_div
	    								z1.clone(),                      //c_div
	    								z2.clone(),                      //d_div
	    								v1.clone(),
	    								v2.clone(),
	    								v3.clone(),
	    								v4.clone(),
	    								v5.clone(),
	    								v6.clone(),
	    								v7.clone(),
	    								v8.clone(),
	    								v9.clone()
	    								);

	    let mut c_sum = svpok.e1.clone();
	    c_sum.add_assign(&secp_inst, &svpok.e2).unwrap();

	    c_sum == hash_scalar    // comparing e1+e2 from SpecialVerifyPoK and evaluation of the scalar-hash
	}
}

#[derive (Clone)]
pub struct QuisquisPRPoK {
	e1 : SecretKey,
	e2 : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
	s3 : SecretKey,
	s4 : SecretKey,
}

impl QuisquisPRPoK {
	pub fn new() -> QuisquisPRPoK {
		QuisquisPRPoK {
			e1 : ZERO_KEY,
			e2 : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
			s3 : ZERO_KEY,
			s4 : ZERO_KEY,
		}
	}

	pub fn create_pok_from_decoykey (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		keyimage : PublicKey,
		dkey : SecretKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		f_gen : PublicKey,
		) -> QuisquisPRPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = QuisquisPRPoK::new();
	    let r4 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.e1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s3 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = s3*f + e1*x     where x = g2
	    let v1 = double_base_product(&secp_inst, f_gen.clone(), pubkey.x.clone(), rpok.s3.clone(), rpok.e1.clone());
	    //v2 = s1*e2 + s2*g + e1*y        where y = d2
	    let v2 = triple_base_product(&secp_inst, commitment.x.clone(), g_gen, commitment.y.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.e1.clone());
	    //v3 = s2*g + s1*f + e1*z         where z = I_i
	    let v3 = triple_base_product(&secp_inst, g_gen, f_gen, keyimage.clone(), rpok.s2.clone(), rpok.s1.clone(), rpok.e1.clone());
	    //v4 = r4*f
	    let v4 = single_base_product(&secp_inst, f_gen, r4.clone());

	    // Calculation of H(S || V_1 || V_2 || V_3 || V_4)
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
	    hasher.input(v3.serialize_vec(&secp_inst, true));                   // Hash V_3
	    hasher.input(v4.serialize_vec(&secp_inst, true));                   // Hash r_3*h

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of -e_1
	    let mut minus_e1 = rpok.e1.clone();
	    minus_e1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_2
	    rpok.e2 = hash_scalar;                                      // e_2 = H(S...)
	    rpok.e2.add_assign(&secp_inst, &minus_e1).unwrap();         // e_2 = H(S...) - e_1

	    // Calculation of s_3
	    rpok.s4 = a_minus_bx(&secp_inst, r4.clone(), rpok.e2.clone(), dkey);

	    rpok
	}

	pub fn create_pok_from_representation (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		keyimage : PublicKey,
		secret_key : SecretKey,
		amount : u64,
		rand : SecretKey,
		g_gen : PublicKey,
		h_gen : PublicKey,
		f_gen : PublicKey,
		) -> QuisquisPRPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = QuisquisPRPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);
	    let r3 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.e2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s4 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r3*f
	    let v1 = single_base_product(&secp_inst, f_gen, r3.clone());
	    //v2 = r1*e2 + r2*g   
	    let v2 = double_base_product(&secp_inst, commitment.x.clone(), g_gen, r1.clone(), r2.clone());
	    //v3 = r2*g + r1*f
	    let v3 = double_base_product(&secp_inst, g_gen, f_gen, r2.clone(), r1.clone());
	    //v4 = s4*f + e2*z
	    let v4 = double_base_product(&secp_inst, f_gen, keyimage.clone(), rpok.s4.clone(), rpok.e2.clone());

	    // Calculation of H(S || V_1 || V_2 || V_3 || V_4)
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
	    hasher.input(v3.serialize_vec(&secp_inst, true));                   // Hash V_3
	    hasher.input(v4.serialize_vec(&secp_inst, true));                   // Hash V_4

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of -e_2
	    let mut minus_e2 = rpok.e2.clone();
	    minus_e2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of e_1
	    rpok.e1 = hash_scalar;                                      // e_1 = H(S...)
	    rpok.e1.add_assign(&secp_inst, &minus_e2).unwrap();         // e_1 = H(S...) - e_2

	    rpok.s1 = a_minus_bx(&secp_inst, r1.clone(), rpok.e1.clone(), secret_key);
	    rpok.s2 = a_minus_bx(&secp_inst, r2.clone(), rpok.e1.clone(), amount_to_key(&secp_inst, amount));
	    rpok.s3 = a_minus_bx(&secp_inst, r3.clone(), rpok.e1.clone(), rand.clone());

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

  		//v1 = s3*f + e1*x     where x = g2
	    let v1 = double_base_product(&secp_inst, f_gen.clone(), pubkey.x.clone(), rpok.s3.clone(), rpok.e1.clone());
	    //v2 = s1*e2 + s2*g + e1*y        where y = d2
	    let v2 = triple_base_product(&secp_inst, commitment.x.clone(), g_gen, commitment.y.clone(), rpok.s1.clone(), rpok.s2.clone(), rpok.e1.clone());
	    //v3 = s2*g + s1*f + e1*z         where z = I_i
	    let v3 = triple_base_product(&secp_inst, g_gen, f_gen, keyimage.clone(), rpok.s2.clone(), rpok.s1.clone(), rpok.e1.clone());
	    //v4 = s4*f + e2*z
	    let v4 = double_base_product(&secp_inst, f_gen, keyimage.clone(), rpok.s4.clone(), rpok.e2.clone());

	    // Calculation of H(S || V_1 || V_2 || V_3 || V_4)
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
	    hasher.input(v3.serialize_vec(&secp_inst, true));                   // Hash V_3
	    hasher.input(v4.serialize_vec(&secp_inst, true));                   // Hash v_4

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    let mut c_sum = rpok.e1.clone(); 
	    c_sum.add_assign(&secp_inst, &rpok.e2).unwrap();

	    c_sum == hash_scalar    // comparing e1+e2 from QuisQuisPRPoK and evaluation of the scalar-hash
	}
}