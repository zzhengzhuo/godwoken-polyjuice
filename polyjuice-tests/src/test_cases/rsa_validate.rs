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
use std::convert::TryInto;

const INIT_CODE: &str = include_str!("./evm-contracts/RsaValidate.bin");
const INIT_ABI: &str = include_str!("./evm-contracts/RsaValidate.abi");

#[test]
fn test_rsa_validate() {
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
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 200000)
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
        let mut n = hex::decode("C067E6850C2F445363C381135146C9ECC98E8C508E67ED528B7C5D024FDF626B19CC274527D9535475026E14D204645759FF7E1CA428839F1C56C5F6680C32C96AD6DB687FDBA8BF80742588CD07C64920F61009D02FECAB610D6FD0D6C48352AC1A8C920B2525605066F334D8D21066BD252E1BB3A5ABE7957129BD4C43D10F").unwrap();
        let e = U256::from_str_radix("65537", 10).unwrap();
        let mut message = b"hello, world".to_vec();
        let mut sig = hex::decode("7acb5e5e1555ea4ffc4b1d1bf16e603b19b810051f9718c6f4eb11b6bf426579467bf932683f0e7c5953aaa1ea558edbf7c587454f7cf8b407be2b20864f07d889448b77a7a1323ee8293f4413c44f6bdb3e2b518f71daff7abc4c7cf685a6e71ce09cdd9a408dec5f6f0657191786317325b433fabcc135ee3ed52e6ea9b715").unwrap();
        let input = contract
            .function("validate")
            .unwrap()
            .encode_input(&vec![
                Token::Uint(e),
                Token::Bytes(n.clone()),
                Token::Bytes(message.clone()),
                Token::Bytes(sig.clone()),
            ])
            .unwrap();
        println!("abi input:{}", hex::encode(&input));
        let mut packed_input = Vec::new();
        packed_input.append(&mut 65537u32.to_le_bytes().to_vec());
        packed_input.append(&mut (n.len() as u32).to_be_bytes().to_vec());
        packed_input.append(&mut n);
        packed_input.append(&mut (6u32.to_be_bytes().to_vec()));
        packed_input.append(&mut (message.len() as u32).to_be_bytes().to_vec());
        packed_input.append(&mut message);
        packed_input.append(&mut (sig.len() as u32).to_be_bytes().to_vec());
        packed_input.append(&mut sig);
        println!("packed input:{}", hex::encode(&packed_input));
        // let input = hex::decode("a3c1c839000007fe00010001").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(21000)
            .gas_price(1)
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
        let log_item = &run_result.logs[0];
        println!("rsa log:{:?}", hex::encode(&log_item.data().raw_data()));
        println!(
            "rsa validate return: {}",
            hex::encode(&run_result.return_data[..])
        );
        let ret = run_result.return_data.clone();
        println!("rsa validate return:{:?}", ret);
        let ret = i32::from_le_bytes(ret.get(..4).unwrap().try_into().unwrap());
        println!("rsa validate return:{}", ret);
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles("Rsa Validate", run_result.used_cycles, 820_000);
    }
}
