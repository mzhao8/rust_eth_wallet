use crate::utils;
use anyhow::{bail, Result};
use secp256k1::{
    rand::{rngs, SeedableRng},
    PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use std::io::BufWriter;
use std::str::FromStr;
use std::{fs::OpenOptions, io::BufReader};
use tiny_keccak::keccak256;
use web3::{
    transports::WebSocket,
    types::{Address, TransactionParameters, H256, U256},
    Web3,
};


#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    pub secret_key: String,
    pub public_key: String,
    pub public_address: String,
}

impl Wallet {
    pub fn new(secret_key: &SecretKey, public_key: &PublicKey) -> Self {
        let addr: Address = public_key_address(&public_key);
        Wallet {
            secret_key: secret_key.to_string(),
            public_key: public_key.to_string(),
            public_address: format!("{:?}", addr),
        }
    }

    pub fn save_to_file(&self, file_path: &str) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path)?;
        let buf_writer = BufWriter::new(file);
        serde_json::to_writer_pretty(buf_writer, self)?;
        Ok(())
    }


    pub fn from_file(file_path: &str) -> Result<Wallet> {
        let file = OpenOptions::new().read(true).open(file_path)?;
        let buf_reader = BufReader::new(file);

        let wallet: Wallet = serde_json::from_reader(buf_reader)?;
        Ok(wallet)
    }

    pub fn get_secret_key(&self) -> Result<SecretKey> {
        let secret_key = SecretKey::from_str(&self.secret_key)?;
        Ok(secret_key)
    }

    pub fn get_public_key(&self) -> Result<PublicKey> {
        let pub_key = PublicKey::from_str(&self.public_key)?;
        Ok(pub_key)
    }

    pub async fn get_balance(&self, web3_connection: &Web3<WebSocket>) -> Result<U256> {
        let wallet_address = Address::from_str(&self.public_address)?;
        let balance = web3_connection.eth().balance(wallet_address, None).await?;

        Ok(balance)
    }

    pub async fn get_balance_in_eth(&self, web3_connection: &Web3<WebSocket>) -> Result<f64> {
        let wei_balance = self.get_balance(web3_connection).await?;

        Ok(utils::wei_to_eth(wei_balance))
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    // secp refers to parameters of the elliptic curve
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rngs::JitterRng::new_with_timer(utils::get_nstime);
    secp.generate_keypair(&mut rng)
}

pub fn public_key_address(public_key: &PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();
   
    // all public keys start with 4 indiciate that it's an uncompressed public key
    debug_assert_eq!(public_key[0], 0x04);

    // ignore the 4 at the beginning
    let hash = keccak256(&public_key[1..]);


    Address::from_slice(&hash[12..])
}

pub async fn establish_web3_connection(url: &str) -> Result<Web3<WebSocket>> {
    let transport = web3::transports::WebSocket::new(url).await?;
    Ok(web3::Web3::new(transport))
}

pub fn create_eth_transaction(to: Address, eth_value: f64) -> TransactionParameters {
    TransactionParameters {
        to: Some(to),
        value: utils::eth_to_wei(eth_value),
        ..Default::default()
    }
}

pub async fn sign_and_send(
    web3: &Web3<WebSocket>,
    transaction: TransactionParameters,
    secret_key: &SecretKey,
    ) -> Result<H256> {
    let signed = web3
        .accounts()
        .sign_transaction(transaction, secret_key)
        .await?;
    
    let transaction_result = web3
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await?;

    Ok(transaction_result)
}
