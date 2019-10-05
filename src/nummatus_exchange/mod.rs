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

use crate::nummatus_nizk::NummatusPoK;

pub struct Nummatus {
  pub pubkey_list: Vec<QPublicKey>,           //Publickey for Quisquis 
  pub commitment_list: Vec<QPublicKey>,       //Quisquis commitment
  pub pedersen_com_list: Vec<PublicKey>,          //Pedersen commitment
  pub pok_list: Vec<NummatusPoK>,             //Nummatus signatures            
  g_basepoint: PublicKey,                     //g
  h_basepoint: PublicKey,                     //h which is computed at height j of Quisquis blockchain
}

impl Nummatus {
  pub fn new(anon_list_size: usize) -> Nummatus {
    let zeropk = PublicKey::new();
    let qzeropk = QPublicKey::new();
    let empty_pok = NummatusPoK::new();
    Nummatus {
      pubkey_list: vec![qzeropk; anon_list_size],
      commitment_list: vec![qzeropk; anon_list_size],
      pedersen_com_list: vec![zeropk; anon_list_size],
      pok_list: vec![empty_pok; anon_list_size],
      g_basepoint: zeropk,
      h_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {

    assert!(self.commitment_list.len() == self.pubkey_list.len());
    assert!(self.commitment_list.len() == self.pedersen_com_list.len());
    assert!(self.commitment_list.len() == self.pok_list.len());
    assert!(self.commitment_list.len() != 0);

    for i in 0..self.commitment_list.len() {
      if NummatusPoK::verify_pok(
        self.pubkey_list[i],
        self.commitment_list[i],
        self.pedersen_com_list[i],
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
  own_keys: Vec<SecretKey>,           
  decoy_keys: Vec<SecretKey>,         
}

impl NummatusExchange {
  pub fn new(alist_size: usize, olist_size: usize) -> NummatusExchange  {

    let mut nproof = Nummatus::new(alist_size);
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

    nproof.g_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    nproof.h_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

    for i in 0..alist_size {   

      if okeys[i] != ZERO_KEY {

        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);

        let r1 = SecretKey::new(&secp_inst, &mut rng);
        let r2 = SecretKey::new(&secp_inst, &mut rng);

        nproof.pubkey_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();   //generating PublicKey from SecretKey
        nproof.pubkey_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
        nproof.pubkey_list[i].y = nproof.pubkey_list[i].x.clone();
        nproof.pubkey_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();


        nproof.commitment_list[i].x = nproof.pubkey_list[i].x.clone();       //generating commitment from PublicKey and amount
        nproof.commitment_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
        let mut v_g = nproof.g_basepoint.clone();
        v_g.mul_assign(&secp_inst, &amount_to_key(&secp_inst, amounts[i])).unwrap();
        let mut r2_d = nproof.pubkey_list[i].y.clone();
        r2_d.mul_assign(&secp_inst, &r2).unwrap();
        nproof.commitment_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_d]).unwrap();

        let mut k_h = nproof.h_basepoint.clone();                            //generating Pedersen commitment from amount and blinding factor
        k_h.mul_assign(&secp_inst, &okeys[i].clone()).unwrap();
        nproof.pedersen_com_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &k_h]).unwrap();
      } 

      else {
        let temp_sk_px = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_py = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cx = SecretKey::new(&secp_inst, &mut rng);
        let temp_sk_cy = SecretKey::new(&secp_inst, &mut rng);

        nproof.pubkey_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_px).unwrap();      //generating PublicKey randomly
        nproof.pubkey_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_py).unwrap();
        nproof.commitment_list[i].x = PublicKey::from_secret_key(&secp_inst, &temp_sk_cx).unwrap();  //generating commitment randomly
        nproof.commitment_list[i].y = PublicKey::from_secret_key(&secp_inst, &temp_sk_cy).unwrap();
        
        dkeys[i] = SecretKey::new(&secp_inst, &mut rng);  
        nproof.pedersen_com_list[i] = nproof.h_basepoint.clone();                //generating Pedersen commitment from blinding factor                     
        nproof.pedersen_com_list[i].mul_assign(&secp_inst, &dkeys[i]).unwrap();
      }
    }

    NummatusExchange  {
      anon_list_size: alist_size,
      nummatus_proof: nproof,
      own_keys: okeys,
      decoy_keys: dkeys,
    }
  }

  pub fn generate_proof(&mut self) -> Nummatus {

    for i in 0..self.anon_list_size {
      if self.own_keys[i] != ZERO_KEY {

        self.nummatus_proof.pok_list[i] = NummatusPoK::create_pok_from_representation(
                                            self.nummatus_proof.pubkey_list[i],
                                            self.nummatus_proof.commitment_list[i],
                                            self.nummatus_proof.pedersen_com_list[i],
                                            self.own_keys[i].clone(),
                                            self.nummatus_proof.h_basepoint,      
                                          );
      } else {
        self.nummatus_proof.pok_list[i] = NummatusPoK::create_pok_from_decoy(
                                            self.nummatus_proof.pubkey_list[i],
                                            self.nummatus_proof.commitment_list[i],
                                            self.nummatus_proof.pedersen_com_list[i],
                                            self.decoy_keys[i].clone(),
                                            self.nummatus_proof.h_basepoint,     
                                          );
      } 
    } 

    Nummatus {
      pubkey_list : self.nummatus_proof.pubkey_list.clone(),
      commitment_list : self.nummatus_proof.commitment_list.clone(),
      pedersen_com_list : self.nummatus_proof.pedersen_com_list.clone(),
      pok_list: self.nummatus_proof.pok_list.clone(),
      g_basepoint: self.nummatus_proof.g_basepoint,
      h_basepoint: self.nummatus_proof.h_basepoint,
    }
  } // end generate_proof

} // end NummatusExchange implementation 
