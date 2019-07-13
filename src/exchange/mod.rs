//use digest::Digest;
//use sha2::Sha256;
use rand::{thread_rng, Rng};
//use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use super::nizk::{RepresentationPoK};

const MAX_AMOUNT_PER_OUTPUT: u64 = 1000;

pub const GENERATOR_G : [u8;65] = [                          //pub : public
    0x04,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
];

pub const GENERATOR_H : [u8;65] = [
    0x04,
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
    0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
    0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
];

#[derive (Copy, Clone)]
pub struct QPublicKey {
    pub x : PublicKey,
    pub y : PublicKey,
}

impl QPublicKey {
    pub fn new() -> QPublicKey {
        QPublicKey {
            x : PublicKey::new(),
            y : PublicKey::new(),
        }
    }
}

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

        simproof.value_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
        simproof.secret_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

        for i in 0..olist_size {
            okeys[i] = SecretKey::new(&secp_inst, &mut rng);
            amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);

            simproof.q_pubkey_list[i].x = PublicKey::new();
            simproof.q_pubkey_list[i].y = simproof.q_pubkey_list[i].x.clone();
            simproof.q_pubkey_list[i].y.mul_assign(&secp_inst, &okeys[i]).unwrap();

            let r = SecretKey::new(&secp_inst, &mut rng);
            simproof.q_com_list[i].x = simproof.q_pubkey_list[i].x.clone();
            simproof.q_com_list[i].x.mul_assign(&secp_inst, &r).unwrap();
            let mut v_g = simproof.value_basepoint.clone();
            v_g.mul_assign(&secp_inst, &RepresentationPoK::amount_to_key(&secp_inst, amounts[i])).unwrap();
            let mut r_hi = simproof.q_pubkey_list[i].y.clone();
            r_hi.mul_assign(&secp_inst, &r).unwrap();
            simproof.q_com_list[i].y = PublicKey::from_combination(&secp_inst, vec![&v_g, &r_hi]).unwrap();

            simproof.own_list[i] = Secp256k1::commit(&secp_inst, amounts[i], okeys[i].clone()).unwrap()        //unsure
                                .to_pubkey(&secp_inst).unwrap();                                 //key-images ... doubt
        }

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

