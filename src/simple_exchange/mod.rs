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

use crate::simple_nizk::SimplePoK;

pub struct Simple {
  pub pubkey_list: Vec<QPublicKey>,           //Public_keys 
  pub commitment_list: Vec<QPublicKey>,       //Commitments
  pub pederson_list: Vec<PublicKey>,          //pederson commitments
  pub pok_list: Vec<SimplePoK>,               //proofs          
  g_basepoint: PublicKey,                     //g
  h_basepoint: PublicKey,                     //h
}

impl Simple {
  pub fn new(anon_list_size: usize) -> Simple {
    let zeropk = PublicKey::new();
    let qzeropk = QPublicKey::new();
    let empty_pok = SimplePoK::new();
    Simple {
      pubkey_list: vec![qzeropk; anon_list_size],
      commitment_list: vec![qzeropk; anon_list_size],
      pederson_list: vec![zeropk; anon_list_size],
      pok_list: vec![empty_pok; anon_list_size],
      g_basepoint: zeropk,
      h_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {

    assert!(self.commitment_list.len() == self.pubkey_list.len());
    assert!(self.commitment_list.len() == self.pederson_list.len());
    assert!(self.commitment_list.len() == self.pok_list.len());
    assert!(self.commitment_list.len() != 0);

    for i in 0..self.commitment_list.len() {
      if SimplePoK::verify_pok(
        self.pubkey_list[i],
        self.commitment_list[i],
        self.pederson_list[i],
        self.h_basepoint,
        self.pok_list[i].clone(),
      ) == false {
        return false;
      }
    }

    true
  }
}

pub struct SimpleExchange {
  own_list_size: usize,
  Simple_proof: Simple,
  own_keys: Vec<SecretKey>,            //k_i
  own_amounts: Vec<u64>,               //v_i
  own_blinding: Vec<SecretKey>,        //w_i
}

impl SimpleExchange {
  pub fn new(olist_size: usize) -> SimpleExchange  {

    let mut simproof = Simple::new(olist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = Vec::new();
    let mut amounts = vec![0u64; olist_size];
    let mut oblind = vec![ZERO_KEY; olist_size];

    let mut rng = thread_rng();

    for i in 0..olist_size {
      okeys.push(SecretKey::new(&secp_inst, &mut rng));
    }

    simproof.g_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    simproof.h_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

    for i in 0..olist_size {
        
        oblind[i] = SecretKey::new(&secp_inst, &mut rng);
        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);

        let r1 = SecretKey::new(&secp_inst, &mut rng);
        let r2 = SecretKey::new(&secp_inst, &mut rng);

        simproof.pubkey_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();   //generating publickey from secretkey
        simproof.pubkey_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
        simproof.pubkey_list[i].y = simproof.pubkey_list[i].x.clone();
        simproof.pubkey_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();


        simproof.commitment_list[i].x = simproof.pubkey_list[i].x.clone();        //generating commitment from publickey and amount
        simproof.commitment_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
        let mut v_g = simproof.g_basepoint.clone();
        v_g.mul_assign(&secp_inst, &amount_to_key(&secp_inst, amounts[i])).unwrap();
        let mut r2_d = simproof.pubkey_list[i].y.clone();
        r2_d.mul_assign(&secp_inst, &r2).unwrap();
        simproof.commitment_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_d]).unwrap();

        let mut w_h = simproof.h_basepoint.clone();                              //generating pederson commitment from blinding factor
        w_h.mul_assign(&secp_inst, &oblind[i].clone()).unwrap();
        simproof.pederson_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &w_h]).unwrap();
    }

    SimpleExchange  {
      own_list_size: olist_size,
      Simple_proof: simproof,
      own_keys: okeys,
      own_amounts: amounts,
      own_blinding: oblind,
    }
  }

  pub fn generate_proof(&mut self) -> Simple {

    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    for i in 0..self.own_list_size {
        let mut minus_blinding = self.own_blinding[i].clone();
        minus_blinding.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

        self.Simple_proof.pok_list[i] = SimplePoK::create_pok_from_representation(
                                            self.Simple_proof.pubkey_list[i],
                                            self.Simple_proof.commitment_list[i],
                                            self.Simple_proof.pederson_list[i],
                                            self.own_keys[i].clone(),
                                            minus_blinding,
                                            self.Simple_proof.h_basepoint,     
                                          );
      } 

    Simple {
      pubkey_list : self.Simple_proof.pubkey_list.clone(),
      commitment_list : self.Simple_proof.commitment_list.clone(),
      pederson_list : self.Simple_proof.pederson_list.clone(),
      pok_list: self.Simple_proof.pok_list.clone(),
      g_basepoint: self.Simple_proof.g_basepoint,
      h_basepoint: self.Simple_proof.h_basepoint,
    }
  } // end generate_proof

} // end SimpleExchange implementation 
