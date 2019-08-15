use digest::Digest;
use sha2::Sha256;
use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::MINUS_ONE_KEY;
use crate::misc::GENERATOR_G;
use crate::misc::GENERATOR_H;
use crate::misc::GENERATOR_F;
use crate::misc::MAX_AMOUNT_PER_OUTPUT;
use crate::misc::amount_to_key;

use crate::Nummatus_nizk::NummatusPoK;

pub struct Nummatus {
  pub pubkey_list: Vec<QPublicKey>,           //Public_keys 
  pub commitment_list: Vec<QPublicKey>,       //Commitments
  pub pederson_list: Vec<PublicKey>,          //pederson commitments
  pub keyimage_list: Vec<PublicKey>,          //key-images
  pub pok_list: Vec<NummatusPoK>,             //proofs            
  g_basepoint: PublicKey,                     //g
  h_basepoint: PublicKey,                     //h
  gj_basepoint: PublicKey,                    //g_j
}

impl Nummatus {
  pub fn new(anon_list_size: usize) -> Nummatus {
    let zeropk = PublicKey::new();
    let qzeropk = QPublicKey::new();
    let empty_pok = NummatusPoK::new();
    Nummatus {
      pubkey_list: vec![qzeropk; anon_list_size],
      commitment_list: vec![qzeropk; anon_list_size],
      pederson_list: vec![zeropk; anon_list_size],
      keyimage_list: vec![zeropk; anon_list_size],
      pok_list: vec![empty_pok; anon_list_size],
      g_basepoint: zeropk,
      h_basepoint: zeropk,
      gj_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {

    assert!(self.commitment_list.len() == self.pubkey_list.len());
    assert!(self.commitment_list.len() == self.pederson_list.len());
    assert!(self.commitment_list.len() == self.keyimage_list.len());
    assert!(self.commitment_list.len() == self.pok_list.len());
    assert!(self.commitment_list.len() != 0);

    for i in 0..self.commitment_list.len() {
      if NummatusPoK::verify_pok(
        self.pubkey_list[i],
        self.commitment_list[i],
        self.pederson_list[i],
        self.keyimage_list[i],
        self.gj_basepoint,
        self.h_basepoint,
        self.pok_list[i].clone(),
      ) == false {
        return false;
      }
    }

    true
  }
}

pub struct NummatusExchange {
  anon_list_size: usize,
  nummatus_proof: Nummatus,
  own_keys: Vec<SecretKey>,           //k_i
  own_amounts: Vec<u64>,              //v_i
  own_blinding: Vec<SecretKey>,       //w_i
  own_minus_blinding: Vec<SecretKey>, //-w_i
  decoy_keys: Vec<SecretKey>,         //u_i
}

impl NummatusExchange {
  pub fn new(alist_size: usize, olist_size: usize) -> NummatusExchange  {

    let mut nproof = Nummatus::new(alist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = Vec::new();
    let mut amounts = vec![0u64; alist_size];
    let mut oblind = vec![ZERO_KEY; alist_size];
    let mut o_minus_blind = vec![ZERO_KEY; alist_size];
    let mut dkeys = vec![ZERO_KEY; alist_size];

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

    nproof.g_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    nproof.h_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
    nproof.gj_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_F).unwrap();

    for i in 0..alist_size {

      oblind[i] = SecretKey::new(&secp_inst, &mut rng); 
      o_minus_blind[i] = oblind[i].clone();
      o_minus_blind[i].mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();     

      if okeys[i] != ZERO_KEY {

        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);

        let r1 = SecretKey::new(&secp_inst, &mut rng);
        let r2 = SecretKey::new(&secp_inst, &mut rng);

        nproof.pubkey_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
        nproof.pubkey_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
        nproof.pubkey_list[i].y = nproof.pubkey_list[i].x.clone();
        nproof.pubkey_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();


        nproof.commitment_list[i].x = nproof.pubkey_list[i].x.clone();
        nproof.commitment_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
        let mut v_g = nproof.g_basepoint.clone();
        v_g.mul_assign(&secp_inst, &amount_to_key(&secp_inst, amounts[i])).unwrap();
        let mut r2_d = nproof.pubkey_list[i].y.clone();
        r2_d.mul_assign(&secp_inst, &r2).unwrap();
        nproof.commitment_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_d]).unwrap();

        let mut w_h = nproof.h_basepoint.clone();
        w_h.mul_assign(&secp_inst, &oblind[i].clone()).unwrap();
        nproof.pederson_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &w_h]).unwrap();

        nproof.keyimage_list[i] = nproof.gj_basepoint.clone();
        nproof.keyimage_list[i].mul_assign(&secp_inst, &okeys[i].clone()).unwrap();
      } 

      else {
        let temp_sk_px = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_py = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cx = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cy = SecretKey::new(&secp_inst, &mut rng);

        nproof.pubkey_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_px).unwrap();
        nproof.pubkey_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_py).unwrap();
        nproof.commitment_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_cx).unwrap();
        nproof.commitment_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_cy).unwrap();
        
        dkeys[i] = SecretKey::new(&secp_inst, &mut rng);  
        nproof.pederson_list[i] = nproof.h_basepoint.clone();                       
        nproof.pederson_list[i].mul_assign(&secp_inst, &oblind[i]).unwrap();
        nproof.keyimage_list[i] = nproof.gj_basepoint.clone();                         
        nproof.keyimage_list[i].mul_assign(&secp_inst, &dkeys[i]).unwrap();
      }
    }

    NummatusExchange  {
      anon_list_size: alist_size,
      nummatus_proof: nproof,
      own_keys: okeys,
      own_amounts: amounts,
      own_blinding: oblind,
      own_minus_blinding: o_minus_blind,
      decoy_keys: dkeys,
    }
  }

  pub fn generate_proof(&mut self) -> Nummatus {

    for i in 0..self.anon_list_size {
      if self.own_keys[i] != ZERO_KEY {

        self.nummatus_proof.pok_list[i] = NummatusPoK::create_pok_from_representation(
                                            self.nummatus_proof.pubkey_list[i],
                                            self.nummatus_proof.commitment_list[i],
                                            self.nummatus_proof.pederson_list[i],
                                            self.nummatus_proof.keyimage_list[i],
                                            self.own_keys[i].clone(),
                                            self.own_minus_blinding[i].clone(),
                                            self.nummatus_proof.gj_basepoint,     //g_j
                                            self.nummatus_proof.h_basepoint,      //h
                                          );
      } else {
        self.nummatus_proof.pok_list[i] = NummatusPoK::create_pok_from_decoy(
                                            self.nummatus_proof.pubkey_list[i],
                                            self.nummatus_proof.commitment_list[i],
                                            self.nummatus_proof.pederson_list[i],
                                            self.nummatus_proof.keyimage_list[i],
                                            self.own_blinding[i].clone(),
                                            self.nummatus_proof.gj_basepoint,     //g_j
                                            self.nummatus_proof.h_basepoint,      //h
                                          );
      } 
    } 

    Nummatus {
      pubkey_list : self.nummatus_proof.pubkey_list.clone(),
      commitment_list : self.nummatus_proof.commitment_list.clone(),
      pederson_list : self.nummatus_proof.pederson_list.clone(),
      keyimage_list: self.nummatus_proof.keyimage_list.clone(),
      pok_list: self.nummatus_proof.pok_list.clone(),
      g_basepoint: self.nummatus_proof.g_basepoint,
      h_basepoint: self.nummatus_proof.h_basepoint,
      gj_basepoint: self.nummatus_proof.gj_basepoint,
    }
  } // end generate_proof

} // end NummatusExchange implementation 
