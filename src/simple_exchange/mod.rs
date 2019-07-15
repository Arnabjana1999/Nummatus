//use digest::Digest;
//use sha2::Sha256;
use rand::{thread_rng, Rng};
//use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use crate::misc::QPublicKey;
use crate::misc::GENERATOR_G;
use crate::misc::GENERATOR_H;
use crate::misc::MAX_AMOUNT_PER_OUTPUT;
use crate::simple_nizk::RepresentationPoK;

pub struct SimpleProof {
    pub q_pubkey_list : Vec<QPublicKey>,
    pub q_com_list : Vec<QPublicKey>,
    pub own_list : Vec<PublicKey>,
    pub rep_pok : RepresentationPoK,
    pub ind_pok : Vec<RepresentationPoK>,
    value_basepoint : PublicKey,
    secret_basepoint : PublicKey,
}

impl SimpleProof {
    pub fn new(own_list_size: usize) -> SimpleProof {
        let zeropk = PublicKey::new();
        let qzeropk = QPublicKey::new();
        let empty_pok = RepresentationPoK::new();
        SimpleProof {
            q_pubkey_list : vec![qzeropk; own_list_size],
            q_com_list : vec![qzeropk; own_list_size],
            own_list : vec![zeropk; own_list_size],
            rep_pok : empty_pok.clone(),
            ind_pok : vec![empty_pok.clone(); own_list_size],          
            value_basepoint : zeropk,
            secret_basepoint : zeropk,
        }
    }

    pub fn verify(&self) -> bool {
        assert!(self.own_list.len() > 0);

        let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

        let mut sum_images = self.own_list[0];
        for i in 1..self.own_list.len() {
            sum_images = PublicKey::from_combination(&secp_inst, vec![&sum_images, &self.own_list[i]]).unwrap(); //sum_images += image
        }

        let mut result : bool;

        for i in 0..self.own_list.len() {
            result = RepresentationPoK::verify_individual_pok(
                    &self.q_pubkey_list[i].y,
                    &self.q_com_list[i].y,
                    &self.own_list[i],
                    &self.q_pubkey_list[i].x,
                    &self.q_com_list[i].x,
                    &self.value_basepoint,
                    &self.secret_basepoint,
                    &self.ind_pok[i]);

            if result == false {
                return false;
            }
        }

        RepresentationPoK::verify_summation_pok(
            &sum_images,
            &self.secret_basepoint,
            &self.value_basepoint,
            &self.rep_pok,
            )
    }
}

pub struct SimpleQuisquisExchange {
    own_list_size : usize,
    simple_proof : SimpleProof,
    own_keys : Vec<SecretKey>,
    own_amounts : Vec<u64>,
}

impl SimpleQuisquisExchange {
    pub fn new(olist_size : usize) -> SimpleQuisquisExchange {

        let mut simproof = SimpleProof::new(olist_size);
        let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
        let mut okeys = vec![ZERO_KEY; olist_size];
        let mut amounts = vec![0u64; olist_size];

        let mut rng = thread_rng();

        //println!("1");
        simproof.value_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
        simproof.secret_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

        for i in 0..olist_size {
            okeys[i] = SecretKey::new(&secp_inst, &mut rng);
            amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);
            let r1 = SecretKey::new(&secp_inst, &mut rng);
            let r2 = SecretKey::new(&secp_inst, &mut rng);
            //println!("2");
            simproof.q_pubkey_list[i].x = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
            simproof.q_pubkey_list[i].x.mul_assign(&secp_inst, &r1).unwrap();
            //println!("3");
            simproof.q_pubkey_list[i].y = simproof.q_pubkey_list[i].x.clone();
            //println!("4");
            simproof.q_pubkey_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();

            //println!("5");
            
            simproof.q_com_list[i].x = simproof.q_pubkey_list[i].x.clone();

            //println!("6");
            simproof.q_com_list[i].x.mul_assign(&secp_inst, &r2).unwrap();
            //println!("7");
            let mut v_g = simproof.value_basepoint.clone();
            v_g.mul_assign(&secp_inst, &RepresentationPoK::amount_to_key(&secp_inst, amounts[i])).unwrap();
            let mut r2_hi = simproof.q_pubkey_list[i].y.clone();
            r2_hi.mul_assign(&secp_inst, &r2).unwrap();
            simproof.q_com_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r2_hi]).unwrap();

            let mut sk_h = simproof.secret_basepoint.clone();
            sk_h.mul_assign(&secp_inst, &okeys[i].clone()).unwrap();
            simproof.own_list[i] = PublicKey::from_combination(&secp_inst, vec![&v_g, &sk_h]).unwrap();

            //simproof.own_list[i] = Secp256k1::commit(&secp_inst, amounts[i], okeys[i].clone()).unwrap()        //unsure
            //                    .to_pubkey(&secp_inst).unwrap();                                 //key-images ... doubt
        }
        //println!("8");

        SimpleQuisquisExchange {
            own_list_size : olist_size,
            simple_proof : simproof,
            own_keys : okeys,
            own_amounts : amounts,
        }
    }

    pub fn generate_proof(&mut self) -> SimpleProof {
        let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
        let mut sum_images = self.simple_proof.own_list[0];
        let mut total_secret_keys = self.own_keys[0].clone();                          //unsure
        let mut sum_amount = self.own_amounts[0];

        for i in 1..self.own_list_size {
            sum_images = PublicKey::from_combination(&secp_inst, vec![&sum_images, &self.simple_proof.own_list[i]]).unwrap(); // sum_outputs += output
            total_secret_keys.add_assign(&secp_inst, &self.own_keys[i]).unwrap();
            sum_amount += &self.own_amounts[i];
        }

        for i in 0..self.own_list_size {
            self.simple_proof.ind_pok[i] = RepresentationPoK::create_individual_pok(
                                        self.simple_proof.q_pubkey_list[i].y,
                                        self.simple_proof.q_com_list[i].y,
                                        self.simple_proof.own_list[i],
                                        self.own_keys[i].clone(),                            //unsure
                                        self.own_amounts[i],
                                        self.simple_proof.q_pubkey_list[i].x,
                                        self.simple_proof.q_com_list[i].x,
                                        self.simple_proof.value_basepoint,
                                        self.simple_proof.secret_basepoint,
                                        );
        }

        self.simple_proof.rep_pok = RepresentationPoK::create_summation_pok(
                                  sum_images,
                                  total_secret_keys,
                                  sum_amount,
                                  self.simple_proof.value_basepoint,     // g
                                  self.simple_proof.secret_basepoint,    // h
                                );

        SimpleProof {
            q_pubkey_list : self.simple_proof.q_pubkey_list.clone(),
            q_com_list : self.simple_proof.q_com_list.clone(),
            own_list : self.simple_proof.own_list.clone(),
            rep_pok : self.simple_proof.rep_pok.clone(),
            ind_pok : self.simple_proof.ind_pok.clone(),
            value_basepoint : self.simple_proof.value_basepoint,
            secret_basepoint : self.simple_proof.secret_basepoint,
        }
    }
}

