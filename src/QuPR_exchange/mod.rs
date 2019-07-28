use digest::Digest;
use sha2::Sha256;
use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::GENERATOR_G;
use crate::misc::GENERATOR_H;
use crate::misc::GENERATOR_F;
use crate::misc::MAX_AMOUNT_PER_OUTPUT;
use crate::misc::amount_to_key;

use crate::QuPR_nizk::SpecialVerifyPoK;
use crate::QuPR_nizk::QuisquisPRPoK;

pub struct QuisquisProof {
  pub pubkey_input_list: Vec<QPublicKey>,           //Public_keys prior update   
  pub pubkey_output_list: Vec<QPublicKey>,          //Public_keys post update  
  pub commitment_input_list: Vec<QPublicKey>,       //Commitments prior update
  pub commitment_output_list: Vec<QPublicKey>,      //Commitments post update
  pub keyimage_list: Vec<PublicKey>,                //key-images
  pub pok_su_list: Vec<SpecialVerifyPoK>,      
  pub pok_pr_list: Vec<QuisquisPRPoK>,          
  g_basepoint: PublicKey,                //g
  h_basepoint: PublicKey,                //h
  f_basepoint: PublicKey,                //f
}

impl QuisquisProof {
  pub fn new(anon_list_size: usize) -> QuisquisProof {
    let zeropk = PublicKey::new();
    let qzeropk = QPublicKey::new();
    let empty_su_pok = SpecialVerifyPoK::new();
    let empty_pr_pok = QuisquisPRPoK::new();
    QuisquisProof {
      pubkey_input_list: vec![qzeropk; anon_list_size],
      pubkey_output_list: vec![qzeropk; anon_list_size],
      commitment_input_list: vec![qzeropk; anon_list_size],
      commitment_output_list: vec![qzeropk; anon_list_size],
      keyimage_list: vec![zeropk; anon_list_size],
      pok_su_list: vec![empty_su_pok; anon_list_size],
      pok_pr_list: vec![empty_pr_pok; anon_list_size],
      g_basepoint: zeropk,
      h_basepoint: zeropk,
      f_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {

    assert!(self.commitment_input_list.len() == self.pubkey_input_list.len());
    assert!(self.commitment_input_list.len() == self.pubkey_output_list.len());
    assert!(self.commitment_input_list.len() == self.commitment_output_list.len());
    assert!(self.commitment_input_list.len() == self.keyimage_list.len());
    assert!(self.commitment_input_list.len() == self.pok_su_list.len());
    assert!(self.commitment_input_list.len() == self.pok_pr_list.len());
    assert!(self.commitment_input_list.len() != 0);

    for i in 0..self.commitment_input_list.len() {
      if SpecialVerifyPoK::verify_pok(
        self.pubkey_input_list[i],
        self.commitment_input_list[i],
        self.pubkey_output_list[i],
        self.commitment_output_list[i],
        self.g_basepoint,
        self.h_basepoint,
        self.f_basepoint,
        self.pok_su_list[i].clone(),
      ) == false {
        return false;
      }
    }

    for i in 0..self.commitment_input_list.len() {
      if QuisquisPRPoK::verify_pok(
        self.pubkey_output_list[i],
        self.commitment_output_list[i],
        self.keyimage_list[i],
        self.g_basepoint,
        self.h_basepoint,
        self.f_basepoint,
        self.pok_pr_list[i].clone(),
      ) == false {
        return false;
      }
    }

    true
  }
}

pub struct QuisquisExchange {
  anon_list_size: usize,
  quisquis_proof: QuisquisProof,
  own_keys: Vec<SecretKey>,     //alpha
  own_amounts: Vec<u64>,        //beta
  own_randomness: Vec<SecretKey>,   //t1
  decoy_keys_seed: SecretKey,
  decoy_keys: Vec<SecretKey>,   //gamma
  decoy_rand1: Vec<SecretKey>,  //eta_1
  decoy_rand2: Vec<SecretKey>,  //eta_2
}

impl QuisquisExchange {
  pub fn new(alist_size: usize, olist_size: usize) -> QuisquisExchange  {

    let mut qproof = QuisquisProof::new(alist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = Vec::new();
    let mut amounts = vec![0u64; alist_size];
    let mut orand = vec![ZERO_KEY; alist_size];
    let mut dkeys = vec![ZERO_KEY; alist_size];
    let mut drand1 = vec![ZERO_KEY; alist_size];
    let mut drand2 = vec![ZERO_KEY; alist_size];

    let mut rng = thread_rng();

    for i in 0..alist_size {
      if i < olist_size {
        okeys.push(SecretKey::new(&secp_inst, &mut rng));
      } else {
        okeys.push(ZERO_KEY)
      }
    }

    // Randomly permuting the own outputs
    okeys.shuffle(&mut rng);

    // Long-term secret key used to seed creation of decoy keys
    let dkeys_seed = SecretKey::new(&secp_inst, &mut rng);

    // Initialize SHA256 to generate decoy keys
    let mut hasher = Sha256::new();

    qproof.g_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    qproof.h_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
    qproof.f_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_F).unwrap();

    for i in 0..alist_size {
      if okeys[i] != ZERO_KEY {
        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);
        orand[i] = SecretKey::new(&secp_inst, &mut rng);

        let r1 = SecretKey::new(&secp_inst, &mut rng);
        let r2 = SecretKey::new(&secp_inst, &mut rng);

        qproof.pubkey_input_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
        qproof.pubkey_input_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
        qproof.pubkey_input_list[i].y = qproof.pubkey_input_list[i].x.clone();
        qproof.pubkey_input_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();

        qproof.commitment_input_list[i].x = qproof.pubkey_input_list[i].x.clone();
        qproof.commitment_input_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
        let mut v_g = qproof.g_basepoint.clone();
        v_g.mul_assign(&secp_inst, &amount_to_key(&secp_inst, amounts[i])).unwrap();
        let mut r2_hi = qproof.pubkey_input_list[i].y.clone();
        r2_hi.mul_assign(&secp_inst, &r2).unwrap();
        qproof.commitment_input_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_hi]).unwrap();

        qproof.pubkey_output_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_F).unwrap();
        qproof.pubkey_output_list[i].x.mul_assign(&secp_inst, &orand[i]).unwrap();
        qproof.pubkey_output_list[i].y = qproof.pubkey_output_list[i].x.clone();
        qproof.pubkey_output_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();

        qproof.commitment_output_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
        qproof.commitment_output_list[i].x.mul_assign(&secp_inst, &orand[i]).unwrap();
        let mut sk_c2 = qproof.commitment_output_list[i].x.clone();
        sk_c2.mul_assign(&secp_inst, &okeys[i]).unwrap();
        qproof.commitment_output_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &sk_c2]).unwrap();

        let mut sk_f = qproof.f_basepoint.clone();
        sk_f.mul_assign(&secp_inst, &okeys[i].clone()).unwrap();
        qproof.keyimage_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &sk_f]).unwrap();

      } 

      else {
        let temp_sk_px = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_py = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cx = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cy = SecretKey::new(&secp_inst, &mut rng);
        qproof.pubkey_input_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_px).unwrap();
        qproof.pubkey_input_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_py).unwrap();
        qproof.commitment_input_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_cx).unwrap();
        qproof.commitment_input_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_cy).unwrap();

        drand1[i] = SecretKey::new(&secp_inst, &mut rng);
        drand2[i] = SecretKey::new(&secp_inst, &mut rng);

        qproof.pubkey_output_list[i].x = qproof.pubkey_input_list[i].x.clone();
        qproof.pubkey_output_list[i].x.mul_assign(&secp_inst, &drand1[i]);
        qproof.pubkey_output_list[i].y = qproof.pubkey_input_list[i].y.clone();
        qproof.pubkey_output_list[i].y.mul_assign(&secp_inst, &drand1[i]);
        let c1 = qproof.commitment_input_list[i].x.clone();
        let mut r2_g1 = qproof.pubkey_input_list[i].x.clone();
        r2_g1.mul_assign(&secp_inst, &drand2[i]).unwrap();
        qproof.commitment_output_list[i].x = PublicKey::from_combination(&secp_inst, vec![&c1, &r2_g1]).unwrap();
        let d1 = qproof.commitment_input_list[i].y.clone();
        let mut r2_h1 = qproof.pubkey_input_list[i].y.clone();
        r2_h1.mul_assign(&secp_inst, &drand2[i]).unwrap();
        qproof.commitment_output_list[i].y = PublicKey::from_combination(&secp_inst, vec![&d1, &r2_h1]).unwrap();

        hasher.input(dkeys_seed.clone());                                                        // Hash k_exch
        hasher.input(qproof.commitment_output_list[i].x.serialize_vec(&secp_inst, true));       // Hash C_i
        hasher.input(qproof.commitment_output_list[i].y.serialize_vec(&secp_inst, true));       // Hash C_i
        dkeys[i] = SecretKey::from_slice(&secp_inst, &hasher.clone().result()).unwrap();
        qproof.keyimage_list[i] = qproof.f_basepoint.clone(); // I_i = SHA256(k_exch, C_i)*G' + 0*H
        qproof.keyimage_list[i].mul_assign(&secp_inst, &dkeys[i]).unwrap();
        hasher.reset();
      }
    }

    QuisquisExchange  {
      anon_list_size: alist_size,
      quisquis_proof: qproof,
      own_keys: okeys,
      own_amounts: amounts,
      own_randomness: orand,
      decoy_keys_seed: dkeys_seed,
      decoy_keys: dkeys,
      decoy_rand1: drand1,
      decoy_rand2: drand2,
    }
  }

  pub fn generate_proof(&mut self) -> QuisquisProof {

    for i in 0..self.anon_list_size {
      if self.own_keys[i] != ZERO_KEY {
        self.quisquis_proof.pok_su_list[i] = SpecialVerifyPoK::create_pok_from_representation(
                                            self.quisquis_proof.pubkey_input_list[i],
                                            self.quisquis_proof.commitment_input_list[i],
                                            self.quisquis_proof.pubkey_output_list[i],
                                            self.quisquis_proof.commitment_output_list[i],
                                            self.own_keys[i].clone(),
                                            self.own_randomness[i].clone(),
                                            self.quisquis_proof.g_basepoint,     //g
                                            self.quisquis_proof.h_basepoint,     //h
                                            self.quisquis_proof.f_basepoint,     //f
                                          );

        self.quisquis_proof.pok_pr_list[i] = QuisquisPRPoK::create_pok_from_representation(
                                            self.quisquis_proof.pubkey_output_list[i],
                                            self.quisquis_proof.commitment_output_list[i],
                                            self.quisquis_proof.keyimage_list[i],
                                            self.own_keys[i].clone(),
                                            self.own_amounts[i],
                                            self.own_randomness[i].clone(),
                                            self.quisquis_proof.g_basepoint,     //g
                                            self.quisquis_proof.h_basepoint,     //h
                                            self.quisquis_proof.f_basepoint,     //f
                                          );
      } else {
        self.quisquis_proof.pok_su_list[i] = SpecialVerifyPoK::create_pok_from_decoy(
                                            self.quisquis_proof.pubkey_input_list[i],
                                            self.quisquis_proof.commitment_input_list[i],
                                            self.quisquis_proof.pubkey_output_list[i],
                                            self.quisquis_proof.commitment_output_list[i],
                                            self.decoy_rand1[i].clone(),
                                            self.decoy_rand2[i].clone(),
                                            self.quisquis_proof.g_basepoint,     //g
                                            self.quisquis_proof.h_basepoint,     //h
                                            self.quisquis_proof.f_basepoint,     //f
                                          );

        self.quisquis_proof.pok_pr_list[i] = QuisquisPRPoK::create_pok_from_decoykey(
                                            self.quisquis_proof.pubkey_output_list[i],
                                            self.quisquis_proof.commitment_output_list[i],
                                            self.quisquis_proof.keyimage_list[i],
                                            self.decoy_keys[i].clone(),
                                            self.quisquis_proof.g_basepoint,     //g
                                            self.quisquis_proof.h_basepoint,     //h
                                            self.quisquis_proof.f_basepoint,     //f
                                          );
      } 
    } 

    QuisquisProof {
      pubkey_input_list : self.quisquis_proof.pubkey_input_list.clone(),
      pubkey_output_list : self.quisquis_proof.pubkey_output_list.clone(),
      commitment_input_list : self.quisquis_proof.commitment_input_list.clone(),
      commitment_output_list : self.quisquis_proof.commitment_output_list.clone(),
      keyimage_list: self.quisquis_proof.keyimage_list.clone(),
      pok_su_list: self.quisquis_proof.pok_su_list.clone(),
      pok_pr_list: self.quisquis_proof.pok_pr_list.clone(),
      g_basepoint: self.quisquis_proof.g_basepoint,
      h_basepoint: self.quisquis_proof.h_basepoint,
      f_basepoint: self.quisquis_proof.f_basepoint,
    }
  } // end generate_proof

} // end QuisquisExchange implementation 
