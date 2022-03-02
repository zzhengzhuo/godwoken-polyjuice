//! Test SimpleStorage
//!   See ./evm-contracts/SimpleStorage.sol

use crate::helper::{
    self, build_eth_l2_script, new_account_script, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use ethabi::{ethereum_types::U256, Contract, Token};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};
// use std::convert::TryInto;

const INIT_CODE: &str = include_str!("./evm-contracts/EmailParse.bin");
const INIT_ABI: &str = include_str!("./evm-contracts/EmailParse.abi");

#[test]
fn test_email_parse() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 2000000000)
        .unwrap();

    let from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance1);
    {
        // Deploy SimpleStorage
        let block_info = new_block_info(0, 1, 0);
        let input = hex::decode(INIT_CODE).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(creator_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        state.apply_run_result(&run_result).expect("update state");
        // 557534 < 560K
        helper::check_cycles("Deploy Rsa Validate", run_result.used_cycles, 720_000);
    }

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let from_balance2 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance2);
    println!(
        "contract account script: {}",
        hex::encode(contract_account_script.as_slice())
    );
    println!(
        "eth address: {}",
        hex::encode(&contract_account_script.args().raw_data().as_ref()[36..])
    );
    {
        // SimpleStorage.set(0x0d10);
        let block_info = new_block_info(0, 2, 0);
        let contract = Contract::load(INIT_ABI.as_bytes()).unwrap();
        // let email = "123";
        let raw_email = include_str!("./emails/qq.eml");
        let email = email_rs::Email::from_str(raw_email).unwrap();
        let dkim = email.dkim_headers.get(0).unwrap();
        let selector = dkim.selector.clone();
        let sdid = dkim.sdid.clone();
        // println!("email: {}",email);
        let n = hex::decode("cfb0520e4ad78c4adb0deb5e605162b6469349fc1fde9269b88d596ed9f3735c00c592317c982320874b987bcc38e8556ac544bdee169b66ae8fe639828ff5afb4f199017e3d8e675a077f21cd9e5c526c1866476e7ba74cd7bb16a1c3d93bc7bb1d576aedb4307c6b948d5b8c29f79307788d7a8ebf84585bf53994827c23a5").unwrap();
        let e = U256::from_str_radix("65537", 10).unwrap();
        let input = contract
            .function("validate")
            .unwrap()
            .encode_input(&vec![
                // Token::Bytes(vec![1,2,3]),
                Token::Uint(e),
                // Token::Bytes(vec![1,1,1]),
                Token::Bytes(n.clone()),
                // Token::Bytes(selector.as_bytes().to_vec()),
                // Token::Bytes(sdid.as_bytes().to_vec()),
                Token::Bytes(raw_email.as_bytes().to_vec()),
            ])
            .unwrap();

        // println!("abi input:{}", hex::encode(&input));
        // let mut packed_input = Vec::new();
        // packed_input.append(&mut 65537u32.to_be_bytes().to_vec());
        // packed_input.append(&mut (n.len() as u32).to_be_bytes().to_vec());
        // packed_input.append(&mut n.clone());
        // packed_input.append(&mut (email.len() as u32).to_be_bytes().to_vec());
        // packed_input.append(&mut email.as_bytes().to_vec());
        // println!("packed input:{}", hex::encode(&packed_input));
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(20000000)
            .gas_price(0)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        println!(
            "dkim validate return: {}",
            hex::encode(&run_result.return_data[..])
        );
        let ret = run_result.return_data.clone();
        println!("dkim validate return:{:?}", ret);
        // let ret = i32::from_le_bytes(ret.get(..4).unwrap().try_into().unwrap());
        // let ret = decode(&[ParamType::Uint(256)], &ret).unwrap();
        // let ret = u32::from_le_bytes(ret.get(..4).unwrap().try_into().unwrap());
        // println!("dkim validate return:{:?}", ret);
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles("Dkim Validate", run_result.used_cycles, 820_000);
    }
}
