use digest::Digest;
use sha2::Sha256;
use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use std::fmt;

static g_global : u64 = 120;

#[derive(PartialEq, PartialOrd, Copy, Clone)]           //for comparison of 2 Pubkeys
pub struct PubKey {
	g : u64,
	h : u64,
}

pub struct KeyPair {                      //(pk,sk)
	pk : PubKey,
	sk : u32,
}

impl PubKey {

	pub fn Gen() -> PubKey {
		let sk : u32 = rand::random::<u32>();
		let r : u32 = rand::random::<u32>();
		PubKey {
			g : g_global.pow(sk),
			h : g_global.pow(r*sk),
		}
	}

	pub fn Gen_full() -> KeyPair {                //not mentioned
		let sk : u32 = rand::random::<u32>();
		let r : u32 = rand::random::<u32>();
		let pk = PubKey {
			g : g_global.pow(sk),
			h : g_global.pow(r*sk),
		};
		KeyPair {
			pk: pk,
			sk: sk,
		}
	}

	pub fn new_sk(sk: u32) -> PubKey {
		let exponent : u32 = rand::random::<u32>();
		let base : u64 = g_global.pow(exponent);
		PubKey {
			g : base,
			h : base.pow(sk),
		}
	}

	pub fn new_fixed(g_val: u64, h_val: u64) -> PubKey {
		PubKey {
			g : g_val,
			h : h_val,
		}
	}

	pub fn Update(&self) -> PubKey {          //Updates public-key based on random r
		let r : u32 = rand::random::<u32>();
		let base_g : u64 = self.g;
		let base_h : u64 = self.h;
		PubKey {
			g : base_g.pow(r),
			h : base_h.pow(r),
		}
	}

	pub fn Update_with_known_r(&self, r: u32) -> PubKey {     //not mentioned
		let base_g : u64 = self.g;
		let base_h : u64 = self.h;
		PubKey {
			g : base_g.pow(r),
			h : base_h.pow(r),
		}
	}
}

#[derive(PartialEq, PartialOrd, Copy, Clone)]
pub struct Commitment {
	c : u64,
	d : u64,
}

impl Commitment {

	pub fn prod_hadamard(&self, com: Commitment) -> Commitment {
		let new_c = self.c * com.c;
		let new_d = self.d * com.d;
		Commitment {
			c: new_c,
			d: new_d,
		}
	}
}

fn commit(pkey: PubKey, bl: u32, r: u32) -> Commitment {     //exponents only u32 is allowed here
	let base_pg : u64  = pkey.g;
	let base_ph : u64 = pkey.h;
	let base_gg : u64 = g_global;
	Commitment {
		c : base_pg.pow(r),
		d : base_gg.pow(bl) * base_ph.pow(r),
	}
}

fn VerifyKP(pk: PubKey, sk: u32) -> bool {
	let base_g = pk.g;
	let base_h = pk.h;
	let exp = base_g.pow(sk);

	if exp == base_h {
		true
	}
	else {
		false
	}
}

fn VerifyUpdate(pk_prime: PubKey, pk: PubKey, r: u32) -> bool {    //not required
	
	if(pk.Update_with_known_r(r) == pk_prime) {
		true
	}
	else {
		false
	}
}

#[derive(PartialEq, PartialOrd, Copy, Clone)]
pub struct Account {     //pseudonym for a user
	pk : PubKey,
	com : Commitment,
}

#[derive(PartialEq, PartialOrd, Copy, Clone)]
pub struct Account_full {      //not mentioned
	acct : Account,
	sk : u32,
}

impl Account {

	pub fn GenAcct(bl: u32) -> Account_full {
		let key_pair = PubKey::Gen_full();
		let pk = key_pair.pk;
		let sk = key_pair.sk;
		let r : u32 = rand::random::<u32>();
		let com = commit(pk.clone(), bl, r);      //clone used here
		let acct = Account {
			pk: pk,
			com: com,
		};
		Account_full {
			acct: acct,
			sk: sk,
		}
	}

	pub fn UpdateAcct(&self, acct: Account, v: u32, r1: u32, r2: u32) -> Account {
		let pk = self.pk;
		let com = self.com;
		let com_extra = commit(pk, v, r2);
		pk.Update_with_known_r(r1);
		com.prod_hadamard(com_extra);
		Account {
			pk: pk,
			com: com,
		}
	}

}

pub fn VerifyCom(pk: PubKey, com: Commitment, sk: u32, bl: u32) -> bool {   //Verify in a different way
	let pk_g_exp_r = com.c;                                                 
	let pk_h_exp_r_with_bl = com.d;
	let pk_h_exp_r_without_bl = pk_g_exp_r.pow(sk);
	let g_global_exp_bl = pk_h_exp_r_with_bl/pk_h_exp_r_without_bl;
	g_global_exp_bl == g_global.pow(bl)
}

pub fn VerifyAcct(acct: Account, sk: u32, bl: u32) -> bool {
	let pk = acct.pk;
	let com = acct.com;
	VerifyCom(pk, com, sk, bl)	                                 //bl belongs to V ??
}

pub fn VerifyUpdateAcct(acct_prime: Account, acct: Account, v: u32, r1: u32, r2: u32) -> bool {
	acct.UpdateAcct(acct, v, r1, r2);
	acct == acct_prime                                     //v belongs to V ??
}

//--------------------------------------------------------------------------------------------------------------
#[derive(PartialEq, PartialOrd, Clone)]
pub struct Transaction {
	inputs : Vec<Account>,
	outputs : Vec<Account>,
	//pi : Proof,
}

impl Transaction {

	pub fn permutation_1(&mut self, s_star: u32, R_star: Vec<u32>, A_star: Vec<u32>) -> Vec<u32> {
		let input_vec = self.inputs.clone();
		let mut output_vec : Vec<Account> = Vec::new();
		let mut permutation : Vec<u32> = Vec::new();
		let length = vec.len();
		let mut index : u32 = 1;

		for j in 0..(len-1) {            //default initialization of permutation vector
			permutation.push(0);
		}

		output_vec.push(input_vec[s_star]);    //s*
		permutation[s_star] = index;
		index+=1;

		for i in R_star {                      //R*
			output_vec.push(input_vec[i]);
			permutation[i]=index;
			index+=1;
		}

		for i in A_star {                       //A*
			output_vec.push(input_vec[i]);
			permutation[i]=index;
			index+=1;
		}

		self.outputs = output_vec;
		permutation
	}
}

//----------------------------------------------------------------------------------------------------------------------------

#[derive(PartialEq, PartialOrd, Clone)]
pub struct UTXO {
	utxo : Vec<Account>,
}

impl UTXO {

	pub fn fetch_accounts(&mut self, n: u32) -> UTXO {   //fetch n accounts from utxo and remove them from current utxo
		let vec = self.utxo.clone();
		let mut vec_taken : Vec<Account> = Vec::new();    //initializing
		let mut vec_rem : Vec<Account> = Vec::new();
		let length = vec.len();
		let len = length as u32;               //type-casting

		let mut flag : bool;
		let mut taken_count = 0;
		let mut k : u32;
		let mut rng = rand::thread_rng();

		for i in 0..(len-1) {

			let index = i as usize;            //type-casting
			flag = false;
			k = rng.gen_range(0, 2);           //check whether it generates 0/1 randomly ??
			if k==0 {
				flag = false;
			}
			if k==1 {
				flag = true;
			}
			if taken_count == n {
				flag = false;
			}
			if len-i == n-taken_count {
				flag = true;
			}
			if flag {
				taken_count+=1;
				vec_taken.push(vec[index]);
			}
			if !flag {
				vec_rem.push(vec[index]);
			}
		}

		self.utxo = vec_rem;              //self-mutation done here
		UTXO {
			utxo : vec_taken,
		}
	}

	pub fn add_accounts(&mut self, vec: Vec<Account>) {   //add some accounts to utxo
		let mut v = self.utxo.clone();
		for i in vec {
			v.push(i);
		}
		self.utxo = v;               //self-mutation done here
	}
}

//----------------------------------------------------------------------------------------------------------------------------

pub struct Proof_shuffle {

}

pub struct Proof_vu {
	z : u32,                 //from Fp
	c : u32,                 //output of sha2 hash
}

pub struct Proof_com {
	x : u32,
	z : Vec<u32>,
}

pub struct Proof_range_sk {
	x : u32,
	z : Vec<u32>,
	//range-proof??
}

pub struct Proof_transaction {
	p1 : Proof_vu,
	p2 : Proof_com,
	p3 : Proof_vu,
	p4 : Proof_range_sk,
}

pub struct Proof {
	sigma_1 : Proof_shuffle,
	sigma_2 : ,
	sigma_3 : Proof_shuffle,
}

fn main() {
	let a = PublicKey::new();
}