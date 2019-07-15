use digest::Digest;
use sha2::Sha256;
use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::MINUS_ONE_KEY;
use crate::misc::amount_to_key;

#[derive (Clone)]
pub struct QuisquisPoK {
	c1 : SecretKey,
	c2 : SecretKey,
	s1 : SecretKey,
	s2 : SecretKey,
	s3 : SecretKey,
}

impl QuisquisPoK {
	pub fn new() -> QuisquisPoK {
		QuisquisPoK {
			c1 : ZERO_KEY,
			c2 : ZERO_KEY,
			s1 : ZERO_KEY,
			s2 : ZERO_KEY,
			s3 : ZERO_KEY,
		}
	}

	pub fn create_pok_from_decoykey (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		keyimage : PublicKey,
		dkey : SecretKey,
		value_gen : PublicKey,
		secret_gen : PublicKey,
		) -> QuisquisPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = QuisquisPoK::new();
	    let r3 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.c1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s1 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s2 = SecretKey::new(&secp_inst, &mut rng);

	     //v1 = s1*g1 + c1*x     where x = h_i
	    let mut s1_g1 = pubkey.x.clone();
	    s1_g1.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut c1_x = pubkey.y.clone();
	    c1_x.mul_assign(&secp_inst, &rpok.c1).unwrap();
	    let v1 = PublicKey::from_combination(&secp_inst, vec![&s1_g1, &c1_x]).unwrap();


	    //v2 = s1*g2 + s2*g + c1*y        where y = d_i
	    let mut s1_g2 = commitment.x.clone();
	    s1_g2.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut s2_g = value_gen.clone();
	    s2_g.mul_assign(&secp_inst, &rpok.s2).unwrap();
	    let mut c1_y = commitment.y.clone();
	    c1_y.mul_assign(&secp_inst, &rpok.c1).unwrap();
	    let v2 = PublicKey::from_combination(&secp_inst, vec![&s1_g2, &s2_g, &c1_y]).unwrap();

	    //v3 = s2*g + s1*h + c1*z         where z = I_i
	    let mut s1_h = secret_gen.clone();
	    s1_h.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut c1_z = keyimage.clone();
	    c1_z.mul_assign(&secp_inst, &rpok.c1).unwrap();
	    let v3 = PublicKey::from_combination(&secp_inst, vec![&s2_g, &s1_h, &c1_z]).unwrap();

	    //v4 = r3*h
	    let mut r3_h = secret_gen.clone();
	    r3_h.mul_assign(&secp_inst, &r3).unwrap();

	    // Calculation of H(S || V_1 || V_2 || V_3 || r_3*h)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));            // Hash g
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash g1
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash g2
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));           // Hash h
	    hasher.input(pubkey.y.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash y
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash z
	    hasher.input(v1.serialize_vec(&secp_inst, true));                   // Hash V_1
	    hasher.input(v2.serialize_vec(&secp_inst, true));                   // Hash V_2
	    hasher.input(v3.serialize_vec(&secp_inst, true));                   // Hash V_3
	    hasher.input(r3_h.serialize_vec(&secp_inst, true));                 // Hash r_3*h

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of -c_1
	    let mut minus_c1 = rpok.c1.clone();
	    minus_c1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of c_2
	    rpok.c2 = hash_scalar;                                      // c_2 = H(S...r_3*G')
	    rpok.c2.add_assign(&secp_inst, &minus_c1).unwrap();         // c_2 = H(S...r_3*G') - c_1

	    // Calculation of s_3
	    rpok.s3 = dkey;                                             // s_3 = gamma
	    rpok.s3.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_3 = -gamma
	    rpok.s3.mul_assign(&secp_inst, &rpok.c2).unwrap();          // s_3 = -c_2*gamma
	    rpok.s3.add_assign(&secp_inst, &r3).unwrap();               // s_3 = r_3 - c_2*gamma

	    rpok
	}

	pub fn create_pok_from_representation (
		pubkey : QPublicKey,
		commitment : QPublicKey,
		keyimage : PublicKey,
		secret_key : SecretKey,
		amount : u64,
		value_gen : PublicKey,
		secret_gen : PublicKey
		) -> QuisquisPoK {

		let mut rng = thread_rng();
	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

	    let mut rpok = QuisquisPoK::new();
	    let r1 = SecretKey::new(&secp_inst, &mut rng);
	    let r2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.c2 = SecretKey::new(&secp_inst, &mut rng);
	    rpok.s3 = SecretKey::new(&secp_inst, &mut rng);

	    //v1 = r1*g1
	    let mut r1_g1 = pubkey.x.clone();
	    r1_g1.mul_assign(&secp_inst, &r1).unwrap();

		//v2 = r1*g2 + r2*g   
	    let mut r1_g2 = commitment.x.clone();
	    r1_g2.mul_assign(&secp_inst, &r1).unwrap();
	    let mut r2_g = value_gen.clone();
	    r2_g.mul_assign(&secp_inst, &r2).unwrap();
	    let r1g2_r2g = PublicKey::from_combination(&secp_inst, vec![&r1_g2, &r2_g]).unwrap();

	    //v3 = r2*g + r1*h
	    let mut r1_h = secret_gen.clone();
	    r1_h.mul_assign(&secp_inst, &r1).unwrap();
	    let r2g_r1h = PublicKey::from_combination(&secp_inst, vec![&r2_g, &r1_h]).unwrap();

	    //v4 = s3*h + c2*z
	    let mut s3_h = secret_gen.clone();
	    s3_h.mul_assign(&secp_inst, &rpok.s3).unwrap();
	    let mut c2_z = keyimage.clone();
	    c2_z.mul_assign(&secp_inst, &rpok.c2).unwrap();
	    let v4 = PublicKey::from_combination(&secp_inst, vec![&s3_h, &c2_z]).unwrap();

	    // Calculation of H(S || V_1 || V_2 || V_3 || r_3*h)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));            // Hash g
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash g1
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash g2
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));           // Hash h
	    hasher.input(pubkey.y.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash y
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash z
	    hasher.input(r1_g1.serialize_vec(&secp_inst, true));                // Hash r1_g1
	    hasher.input(r1g2_r2g.serialize_vec(&secp_inst, true));             // Hash r1g2_r2g
	    hasher.input(r2g_r1h.serialize_vec(&secp_inst, true));              // Hash r2g_r1h
	    hasher.input(v4.serialize_vec(&secp_inst, true));                   // Hash V_4

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    // Calculation of -c_2
	    let mut minus_c2 = rpok.c2.clone();
	    minus_c2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

	    // Calculation of c_1
	    rpok.c1 = hash_scalar;                                      // c_1 = H(S...r_3*G')
	    rpok.c1.add_assign(&secp_inst, &minus_c2).unwrap();         // c_1 = H(S...r_3*G') - c_2

	    // Calculation of s_1
	    rpok.s1 = secret_key;                                       // s_1 = alpha
	    rpok.s1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_1 = -alpha
	    rpok.s1.mul_assign(&secp_inst, &rpok.c1).unwrap();          // s_1 = -c_1*alpha
	    rpok.s1.add_assign(&secp_inst, &r1).unwrap();               // s_1 = r_1 - c_1*alpha

	    // Calculation of s_2
	    rpok.s2 = amount_to_key(&secp_inst, amount);   // s_2 = beta
	    rpok.s2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_2 = -beta
	    rpok.s2.mul_assign(&secp_inst, &rpok.c1).unwrap();          // s_2 = -c_1*beta
	    rpok.s2.add_assign(&secp_inst, &r2).unwrap();               // s_2 = r_2 - c_1*beta

	    rpok
	}

  	pub fn verify_pok (
  		pubkey : &QPublicKey,
  		commitment : &QPublicKey,
  		keyimage : &PublicKey,
  		value_gen : &PublicKey,
  		secret_gen : &PublicKey,
  		rpok : &QuisquisPoK
  		) -> bool {

  		let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

  		// Calculation of V_1 = s1*g1 + c1*x    where x = h_i
	    let mut s1_g1 = pubkey.x.clone();
	    s1_g1.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut c1_x = pubkey.y.clone();
	    c1_x.mul_assign(&secp_inst, &rpok.c1).unwrap();
	    let v1 = PublicKey::from_combination(&secp_inst, vec![&s1_g1, &c1_x]).unwrap();

	    // Calculation of V_2 = s1*g2 + s2*g + c1*y    where y = d_i
	    let mut s1_g2 = commitment.x.clone();
	    s1_g2.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut s2_g = value_gen.clone();
	    s2_g.mul_assign(&secp_inst, &rpok.s2).unwrap();
	    let mut c1_y = commitment.y.clone();
	    c1_y.mul_assign(&secp_inst, &rpok.c1).unwrap();
	    let v2 = PublicKey::from_combination(&secp_inst, vec![&s1_g2, &s2_g, &c1_y]).unwrap();

	    // Calculation of V_3 = s2*g + s1*h + c1*z   where z = I_i
	    let mut s1_h = secret_gen.clone();
	    s1_h.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut c1_z = keyimage.clone();
	    c1_z.mul_assign(&secp_inst, &rpok.c1).unwrap();
	    let v3 = PublicKey::from_combination(&secp_inst, vec![&s2_g, &s1_h, &c1_z]).unwrap();

	    // Calculation of V_4 = s3*h + c2*z   where z = I_i
	    let mut s3_h = secret_gen.clone();
	    s3_h.mul_assign(&secp_inst, &rpok.s3).unwrap();
	    let mut c2_z = keyimage.clone();
	    c2_z.mul_assign(&secp_inst, &rpok.c2).unwrap();
	    let v4 = PublicKey::from_combination(&secp_inst, vec![&s3_h, &c2_z]).unwrap();

	    // Calculation of H(S || V_1 || V_2 || V_3 || V_4)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));            // Hash g
	    hasher.input(pubkey.x.serialize_vec(&secp_inst, true));             // Hash g1
	    hasher.input(commitment.x.serialize_vec(&secp_inst, true));         // Hash g2
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));           // Hash h
	    hasher.input(pubkey.y.serialize_vec(&secp_inst, true));             // Hash x
	    hasher.input(commitment.y.serialize_vec(&secp_inst, true));         // Hash y
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));             // Hash z
	    hasher.input(v1.serialize_vec(&secp_inst, true));                   // Hash V_1
	    hasher.input(v2.serialize_vec(&secp_inst, true));                   // Hash V_2
	    hasher.input(v3.serialize_vec(&secp_inst, true));                   // Hash V_3
	    hasher.input(v4.serialize_vec(&secp_inst, true));                   // Hash V_4

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    let mut c_sum = rpok.c1.clone();
	    c_sum.add_assign(&secp_inst, &rpok.c2).unwrap();

	    c_sum == hash_scalar    // comparing c1+c2 from QuisquisPoK and evaluation of the scalar-hash
	}
}