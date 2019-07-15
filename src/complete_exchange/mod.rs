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
use crate::misc::MAX_AMOUNT_PER_OUTPUT;
use crate::misc::amount_to_key;

use crate::complete_nizk::QuisquisPoK;

pub struct QuisquisProof {
  pub pubkey_list: Vec<QPublicKey>,          //Public_keys   
  pub commitment_list: Vec<QPublicKey>,      //Commitments
  pub keyimage_list: Vec<PublicKey>,         //key-images
  pub pok_list: Vec<QuisquisPoK>,            //sigma 5-tuple
  value_basepoint: PublicKey,                //g
  secret_basepoint: PublicKey,               //h
}

impl QuisquisProof {
  pub fn new(anon_list_size: usize) -> QuisquisProof {
    let zeropk = PublicKey::new();
    let qzeropk = QPublicKey::new();
    let empty_pok = QuisquisPoK::new();
    QuisquisProof {
      pubkey_list: vec![qzeropk; anon_list_size],
      commitment_list: vec![qzeropk; anon_list_size],
      keyimage_list: vec![zeropk; anon_list_size],
      pok_list: vec![empty_pok; anon_list_size],
      value_basepoint: zeropk,
      secret_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {

    assert!(self.commitment_list.len() == self.pubkey_list.len());
    assert!(self.commitment_list.len() == self.keyimage_list.len());
    assert!(self.commitment_list.len() == self.pok_list.len());
    assert!(self.commitment_list.len() != 0);

    for i in 0..self.commitment_list.len() {
      if QuisquisPoK::verify_pok(
        &self.pubkey_list[i],
        &self.commitment_list[i],
        &self.keyimage_list[i],
        &self.value_basepoint,
        &self.secret_basepoint,
        &self.pok_list[i],
      ) == false {
        return false;
      } // end if
    } // end for

    true
  }
}

pub struct QuisquisExchange {
  anon_list_size: usize,
  quisquis_proof: QuisquisProof,
  own_keys: Vec<SecretKey>,     //alpha
  own_amounts: Vec<u64>,        //beta
  decoy_keys_seed: SecretKey,
  decoy_keys: Vec<SecretKey>,   //gamma
}

impl QuisquisExchange {
  pub fn new(alist_size: usize, olist_size: usize) -> QuisquisExchange  {

    let mut qproof = QuisquisProof::new(alist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = Vec::new();
    let mut amounts = vec![0u64; alist_size];
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

    // Long-term secret key used to seed creation of decoy keys
    let dkeys_seed = SecretKey::new(&secp_inst, &mut rng);

    // Initialize SHA256 to generate decoy keys
    let mut hasher = Sha256::new();

    qproof.value_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    qproof.secret_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

    for i in 0..alist_size {
      if okeys[i] != ZERO_KEY {
        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);

        let r1 = SecretKey::new(&secp_inst, &mut rng);
        let r2 = SecretKey::new(&secp_inst, &mut rng);

        qproof.pubkey_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
        qproof.pubkey_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
        qproof.pubkey_list[i].y = qproof.pubkey_list[i].x.clone();
        qproof.pubkey_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();

        qproof.commitment_list[i].x = qproof.pubkey_list[i].x.clone();
        qproof.commitment_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
        let mut v_g = qproof.value_basepoint.clone();
        v_g.mul_assign(&secp_inst, &amount_to_key(&secp_inst, amounts[i])).unwrap();
        let mut r2_hi = qproof.pubkey_list[i].y.clone();
        r2_hi.mul_assign(&secp_inst, &r2).unwrap();
        qproof.commitment_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_hi]).unwrap();

        let mut sk_h = qproof.secret_basepoint.clone();
        sk_h.mul_assign(&secp_inst, &okeys[i].clone()).unwrap();
        qproof.keyimage_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &sk_h]).unwrap();

      } 

      else {
        let temp_sk_px = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_py = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cx = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cy = SecretKey::new(&secp_inst, &mut rng);
        qproof.pubkey_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_px).unwrap();
        qproof.pubkey_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_py).unwrap();
        qproof.commitment_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_cx).unwrap();
        qproof.commitment_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_cy).unwrap();
        hasher.input(dkeys_seed.clone());                                                        // Hash k_exch
        hasher.input(qproof.commitment_list[i].x.serialize_vec(&secp_inst, true));       // Hash C_i
        hasher.input(qproof.commitment_list[i].y.serialize_vec(&secp_inst, true));       // Hash C_i
        dkeys[i] = SecretKey::from_slice(&secp_inst, &hasher.clone().result()).unwrap();
        qproof.keyimage_list[i] = qproof.secret_basepoint.clone(); // I_i = SHA256(k_exch, C_i)*G' + 0*H
        qproof.keyimage_list[i].mul_assign(&secp_inst, &dkeys[i]).unwrap();
        hasher.reset();
      }
    }

    QuisquisExchange  {
      anon_list_size: alist_size,
      quisquis_proof: qproof,
      own_keys: okeys,
      own_amounts: amounts,
      decoy_keys_seed: dkeys_seed,
      decoy_keys: dkeys,
    }
  }

  pub fn generate_proof(&mut self) -> QuisquisProof {

    for i in 0..self.anon_list_size {
      if self.own_keys[i] != ZERO_KEY {
        self.quisquis_proof.pok_list[i] = QuisquisPoK::create_pok_from_representation(
                                            self.quisquis_proof.pubkey_list[i],
                                            self.quisquis_proof.commitment_list[i],
                                            self.quisquis_proof.keyimage_list[i],
                                            self.own_keys[i].clone(),
                                            self.own_amounts[i],
                                            self.quisquis_proof.value_basepoint,     // g
                                            self.quisquis_proof.secret_basepoint,    // h
                                          );
      } else {
        self.quisquis_proof.pok_list[i] = QuisquisPoK::create_pok_from_decoykey(
                                            self.quisquis_proof.pubkey_list[i],
                                            self.quisquis_proof.commitment_list[i],
                                            self.quisquis_proof.keyimage_list[i],
                                            self.decoy_keys[i].clone(),
                                            self.quisquis_proof.value_basepoint,     // g
                                            self.quisquis_proof.secret_basepoint,    // h
                                          );
      } // end if-else
    } // end for

    QuisquisProof {
      pubkey_list : self.quisquis_proof.pubkey_list.clone(),
      commitment_list : self.quisquis_proof.commitment_list.clone(),
      keyimage_list: self.quisquis_proof.keyimage_list.clone(),
      pok_list: self.quisquis_proof.pok_list.clone(),
      value_basepoint: self.quisquis_proof.value_basepoint,
      secret_basepoint: self.quisquis_proof.secret_basepoint,
    }
  } // end generate_proof

} // end QuisquisExchange implementation 
