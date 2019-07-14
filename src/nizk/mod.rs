use digest::Digest;
use sha2::Sha256;
use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

/// The number curve_order-1 encoded as a secret key
pub const MINUS_ONE_KEY: SecretKey = SecretKey([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
]);

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

	pub fn create_individual_pok (
		pub_y : PublicKey,     //h_i    x
		output : PublicKey,    //d_i    y
		keyimage : PublicKey,   //I_i   z
		secret_key : SecretKey,  //alpha
		amount : u64,            //beta
		pub_x_gen : PublicKey,   //g_i    g1
		com_x_gen : PublicKey,   //c_i    g2
		value_gen : PublicKey,   //g
		secret_gen : PublicKey,  //h
		) -> RepresentationPoK {

		let mut rng = thread_rng();
		let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

		let mut rep_pok = RepresentationPoK::new();
    	let r1 = SecretKey::new(&secp_inst, &mut rng);
    	let r2 = SecretKey::new(&secp_inst, &mut rng);

    	//Calculation of r1*g1
    	let mut r1_g1 = pub_x_gen.clone();
    	r1_g1.mul_assign(&secp_inst, &r1).unwrap();

    	//Calculation of r1*g2 + r2*g
    	let mut r1_g2 = com_x_gen.clone();
    	r1_g2.mul_assign(&secp_inst, &r1).unwrap();
    	let mut r2_g = value_gen.clone();
    	r2_g.mul_assign(&secp_inst, &r2).unwrap();
    	let r1g2_r2g = PublicKey::from_combination(&secp_inst, vec![&r1_g2, &r2_g]).unwrap();

    	//Calculation of r2*g + r1*h
    	let mut r1_h = secret_gen.clone();
    	r1_h.mul_assign(&secp_inst, &r1).unwrap();
    	let r2g_r1h = PublicKey::from_combination(&secp_inst, vec![&r2_g, &r1_h]).unwrap();

    	// Calculation of H(S || r1*g1 || r1*g2 + r2*g || r2*g + r1*h)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));     // Hash g
	    hasher.input(pub_x_gen.serialize_vec(&secp_inst, true));     // Hash g1
	    hasher.input(com_x_gen.serialize_vec(&secp_inst, true));     // Hash g2
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));    // Hash h

	    hasher.input(pub_y.serialize_vec(&secp_inst, true));         // Hash x
	    hasher.input(output.serialize_vec(&secp_inst, true));        // Hash y
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));      // Hash z

	    hasher.input(r1_g1.serialize_vec(&secp_inst, true));         // Hash r1*g1
	    hasher.input(r1g2_r2g.serialize_vec(&secp_inst, true));      // Hash r1*g2 + r2*g
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
	    rep_pok.s2 = RepresentationPoK::amount_to_key(&secp_inst, amount);    // s_2 = beta
	    rep_pok.s2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();     // s_2 = -beta
	    rep_pok.s2.mul_assign(&secp_inst, &rep_pok.c).unwrap();         // s_2 = -c*beta
	    rep_pok.s2.add_assign(&secp_inst, &r2).unwrap();                // s_2 = r_2 - c*beta

	    rep_pok
	}

	pub fn create_summation_pok (
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
	    rep_pok.s2 = RepresentationPoK::amount_to_key(&secp_inst, amount);    // s_2 = beta
	    rep_pok.s2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_2 = -beta
	    rep_pok.s2.mul_assign(&secp_inst, &rep_pok.c).unwrap();         // s_2 = -c*beta
	    rep_pok.s2.add_assign(&secp_inst, &r2).unwrap();               // s_2 = r_2 - c*beta

	    rep_pok
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

	 pub fn verify_individual_pok (
	 	pub_y: &PublicKey,       //x
	    output: &PublicKey,      //y
	    keyimage: &PublicKey,    //z
	    pub_x_gen : &PublicKey,   //g_i    g1
		com_x_gen : &PublicKey,   //c_i    g2
		value_gen : &PublicKey,   //g
		secret_gen : &PublicKey,  //h
	    rpok: &RepresentationPoK
	  ) -> bool {

	    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
	    //println!("1");
	    //rpok.c = MINUS_ONE_KEY;
	    //rpok.s1 = MINUS_ONE_KEY;
	    //rpok.s2 = MINUS_ONE_KEY;

	    // Calculation of V_1 = s1*g1 + c*x    where x = h_i
	    let mut s1_g1 = pub_x_gen.clone();
	    //println!("2");
	    s1_g1.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    //println!("3");
	    let mut c_x = pub_y.clone();
	    //println!("4");
	    c_x.mul_assign(&secp_inst, &rpok.c).unwrap();
	    //println!("5");
	    let v1 = PublicKey::from_combination(&secp_inst, vec![&s1_g1, &c_x]).unwrap();

	    //println!("2");
	    // Calculation of V_2 = s1*g2 + s2*g + c*y    where y = d_i
	    let mut s1_g2 = com_x_gen.clone();
	    s1_g2.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut s2_g = value_gen.clone();
	    s2_g.mul_assign(&secp_inst, &rpok.s2).unwrap();
	    let mut c_y = output.clone();
	    c_y.mul_assign(&secp_inst, &rpok.c).unwrap();
	    let v2 = PublicKey::from_combination(&secp_inst, vec![&s1_g2, &s2_g, &c_y]).unwrap();

	    //println!("3");
	    // Calculation of V_3 = s2*g + s1*h + c*z   where z = I_i
	    let mut s1_h = secret_gen.clone();
	    s1_h.mul_assign(&secp_inst, &rpok.s1).unwrap();
	    let mut c_z = keyimage.clone();
	    c_z.mul_assign(&secp_inst, &rpok.c).unwrap();
	    let v3 = PublicKey::from_combination(&secp_inst, vec![&s2_g, &s1_h, &c_z]).unwrap();

	    //println!("4");

	    // Calculation of H(S || V_1 || V_2 || V_3)
	    let mut hasher = Sha256::new();
	    hasher.input(value_gen.serialize_vec(&secp_inst, true));    // Hash g
	    hasher.input(pub_x_gen.serialize_vec(&secp_inst, true));    // Hash g1
	    hasher.input(com_x_gen.serialize_vec(&secp_inst, true));    // Hash g2
	    hasher.input(secret_gen.serialize_vec(&secp_inst, true));   // Hash h

	    hasher.input(pub_y.serialize_vec(&secp_inst, true));        // Hash h_i
	    hasher.input(output.serialize_vec(&secp_inst, true));       // Hash d_i
	    hasher.input(keyimage.serialize_vec(&secp_inst, true));     // Hash I_i

	    hasher.input(v1.serialize_vec(&secp_inst, true));           // Hash V_1
	    hasher.input(v2.serialize_vec(&secp_inst, true));           // Hash V_2
	    hasher.input(v3.serialize_vec(&secp_inst, true));           // Hash V_3

	    //println!("5");

	    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

	    let c = rpok.c.clone();

	    c == hash_scalar    // comparing c from QuisquisPoK and evaluation of the scalar-hash
	  }

	  pub fn verify_summation_pok (
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