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

use crate::simple_nizk::SpecialVerifyPoK;
use crate::simple_nizk::QuisquisPRPoK;
use crate::simple_nizk::RepresentationPoK;

pub struct SimpleProof {
  pub pubkey_input_list: Vec<QPublicKey>,           //Public_keys   
  pub pubkey_output_list: Vec<QPublicKey>,          //Public_keys   
  pub commitment_input_list: Vec<QPublicKey>,       //Commitments
  pub commitment_output_list: Vec<QPublicKey>,      //Commitments
  pub keyimage_list: Vec<PublicKey>,                //key-images
  pub pok_su_list: Vec<SpecialVerifyPoK>,      
  pub pok_pr_list: Vec<QuisquisPRPoK>,
  pub pok_rep: RepresentationPoK,          
  g_basepoint: PublicKey,                //g
  h_basepoint: PublicKey,                //h
  f_basepoint: PublicKey,                //f
}

impl SimpleProof {
  pub fn new(own_list_size: usize) -> SimpleProof {
    let zeropk = PublicKey::new();
    let qzeropk = QPublicKey::new();
    let empty_su_pok = SpecialVerifyPoK::new();
    let empty_pr_pok = QuisquisPRPoK::new();
    let empty_rep_pok = RepresentationPoK::new();
    SimpleProof {
      pubkey_input_list: vec![qzeropk; own_list_size],
      pubkey_output_list: vec![qzeropk; own_list_size],
      commitment_input_list: vec![qzeropk; own_list_size],
      commitment_output_list: vec![qzeropk; own_list_size],
      keyimage_list: vec![zeropk; own_list_size],
      pok_su_list: vec![empty_su_pok; own_list_size],
      pok_pr_list: vec![empty_pr_pok; own_list_size],
      pok_rep: empty_rep_pok,
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

    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    for i in 0..self.commitment_input_list.len() {
      if SpecialVerifyPoK::verify_pok(
        self.pubkey_input_list[i],
        self.commitment_input_list[i],
        self.pubkey_output_list[i],
        self.commitment_output_list[i],
        self.f_basepoint,
        self.h_basepoint,
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
        self.f_basepoint,
        self.g_basepoint,
        self.pok_pr_list[i].clone(),
      ) == false {
        return false;
      }
    }

    let mut sum_images = self.keyimage_list[0];
    for i in 1..self.keyimage_list.len() {
        sum_images = PublicKey::from_combination(&secp_inst, vec![&sum_images, &self.keyimage_list[i]]).unwrap(); //sum_images += image
    }

    RepresentationPoK::verify_pok(
        &sum_images,
        &self.f_basepoint,
        &self.g_basepoint,
        &self.pok_rep,
        )
  }
}

pub struct SimpleExchange {
  own_list_size: usize,
  simple_proof: SimpleProof,
  own_keys: Vec<SecretKey>,     //alpha
  own_amounts: Vec<u64>,        //beta
  own_randomness: Vec<SecretKey>,   //t1
}

impl SimpleExchange {
  pub fn new(olist_size: usize) -> SimpleExchange  {

    let mut simproof = SimpleProof::new(olist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = vec![ZERO_KEY; olist_size];
    let mut amounts = vec![0u64; olist_size];
    let mut orand = vec![ZERO_KEY; olist_size];

    let mut rng = thread_rng();
    let mut hasher = Sha256::new();

    simproof.g_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    simproof.h_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
    simproof.f_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_F).unwrap();

    for i in 0..olist_size {
        okeys[i] = SecretKey::new(&secp_inst, &mut rng);
        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);
        orand[i] = SecretKey::new(&secp_inst, &mut rng);
    
        let r1 = SecretKey::new(&secp_inst, &mut rng);
        let r2 = SecretKey::new(&secp_inst, &mut rng);
        
        simproof.pubkey_input_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
        simproof.pubkey_input_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
        simproof.pubkey_input_list[i].y = simproof.pubkey_input_list[i].x.clone();
        simproof.pubkey_input_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();
        
        simproof.commitment_input_list[i].x = simproof.pubkey_input_list[i].x.clone();
        simproof.commitment_input_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
        let mut v_g = simproof.g_basepoint.clone();
        v_g.mul_assign(&secp_inst, &amount_to_key(&secp_inst, amounts[i])).unwrap();
        let mut r2_hi = simproof.pubkey_input_list[i].y.clone();
        r2_hi.mul_assign(&secp_inst, &r2).unwrap();
        simproof.commitment_input_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_hi]).unwrap();

        simproof.pubkey_output_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_F).unwrap();
        simproof.pubkey_output_list[i].x.mul_assign(&secp_inst, &orand[i]).unwrap();
        simproof.pubkey_output_list[i].y = simproof.pubkey_output_list[i].x.clone();
        simproof.pubkey_output_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();

        simproof.commitment_output_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
        simproof.commitment_output_list[i].x.mul_assign(&secp_inst, &orand[i]).unwrap();
        let mut sk_c2 = simproof.commitment_output_list[i].x.clone();
        sk_c2.mul_assign(&secp_inst, &okeys[i]).unwrap();
        simproof.commitment_output_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &sk_c2]).unwrap();

        let mut sk_f = simproof.f_basepoint.clone();
        sk_f.mul_assign(&secp_inst, &okeys[i].clone()).unwrap();
        simproof.keyimage_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &sk_f]).unwrap();
    }
    
    SimpleExchange  {
      own_list_size: olist_size,
      simple_proof: simproof,
      own_keys: okeys,
      own_amounts: amounts,
      own_randomness: orand,
    }
  }

  pub fn generate_proof(&mut self) -> SimpleProof {

    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut sum_images = self.simple_proof.keyimage_list[0];
    let mut total_secret_keys = self.own_keys[0].clone();                       
    let mut sum_amount = self.own_amounts[0];

    for i in 1..self.own_list_size {
        sum_images = PublicKey::from_combination(&secp_inst, vec![&sum_images, &self.simple_proof.keyimage_list[i]]).unwrap(); // sum_outputs += output
        total_secret_keys.add_assign(&secp_inst, &self.own_keys[i]).unwrap();
        sum_amount += &self.own_amounts[i];
    }

    for i in 0..self.own_list_size {
        self.simple_proof.pok_su_list[i] = SpecialVerifyPoK::create_pok(
                                            self.simple_proof.pubkey_input_list[i],
                                            self.simple_proof.commitment_input_list[i],
                                            self.simple_proof.pubkey_output_list[i],
                                            self.simple_proof.commitment_output_list[i],
                                            self.own_keys[i].clone(),
                                            self.own_randomness[i].clone(),
                                            self.simple_proof.f_basepoint,   
                                            self.simple_proof.h_basepoint,   
                                          );

        self.simple_proof.pok_pr_list[i] = QuisquisPRPoK::create_pok(
                                            self.simple_proof.pubkey_output_list[i],
                                            self.simple_proof.commitment_output_list[i],
                                            self.simple_proof.keyimage_list[i],
                                            self.own_keys[i].clone(),
                                            self.own_amounts[i],
                                            self.own_randomness[i].clone(),
                                            self.simple_proof.f_basepoint,   
                                            self.simple_proof.g_basepoint,   
                                          );
      } 

      self.simple_proof.pok_rep = RepresentationPoK::create_pok(
                                    sum_images,
                                    total_secret_keys,
                                    sum_amount,
                                    self.simple_proof.g_basepoint,
                                    self.simple_proof.f_basepoint,
                                    );

    SimpleProof {
      pubkey_input_list : self.simple_proof.pubkey_input_list.clone(),
      pubkey_output_list : self.simple_proof.pubkey_output_list.clone(),
      commitment_input_list : self.simple_proof.commitment_input_list.clone(),
      commitment_output_list : self.simple_proof.commitment_output_list.clone(),
      keyimage_list: self.simple_proof.keyimage_list.clone(),
      pok_su_list: self.simple_proof.pok_su_list.clone(),
      pok_pr_list: self.simple_proof.pok_pr_list.clone(),
      pok_rep: self.simple_proof.pok_rep.clone(),
      g_basepoint: self.simple_proof.g_basepoint,
      h_basepoint: self.simple_proof.h_basepoint,
      f_basepoint: self.simple_proof.f_basepoint,
    }
  } // end generate_proof

} // end SimpleExchange implementation 
