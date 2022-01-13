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
        let n = hex::decode("CC24D40227B53D536227ED0486EF60516896CC56C2FC7684B3D55DE0D35834926E0CE8408C0BDD14ED23F23746595EAE9A035C2F0B9ABD9800F6FF7A92D86DB9BE151852D66F62E6119A5001BF2011A8686F04D009A0A520407065C1A2BB1927A74EA40BA12D35BF6A0BD0C2C28D0062599FF5A2573BEA3F7CA72585CE88BA9A567B2C3C1BF4D94B260F28F513A9865B4D2770E61A60E06E6E8C6348CC3C3B45CCDE585EBA9B1897E4AF20AE74D53D1DAE81A63D50DC2F7B5E7DC1C4BFB4D07AE8AE4CE72F1F9E4BB1569230A76D62D16FDB99A5F645F8ECAC91BB95974DDF7530F9EB3C1703A3461C0D00F851291643D263DCF2253238A019A2E2BB39F4093F").unwrap();
        let e = U256::from_str_radix("65537", 10).unwrap();
        let message = b"hello, world!".to_vec();
        let sig = hex::decode("15ac8324283a66e49755ecc8c3343a2faf4aef13a07cb098071b813fe561053f526f8b7d220077e09bd8df209e4dbedeef93888e258e847a356a909f09c852cbf37c3fa0b7f0f07b4e0b7b8c44652bab3e216af0b9646841bc73cecc10b539e122a2419198c921b6ce21098cff65a8918cfb519c998303d81d2d40f608191e5e70602d926526c39d5f4025b8aec810ee0d1603f2c266ab1af954eba12a4a5d51f6edd2bdb1ab6f64d5597cb62ca692e4d332e87c55afd73aab5c9f2c0b98d4d9950b66f5936562bd7949422c2660fa091bb5c291f57e7d2948c4736d0bdd566334dbd0c0f3b02725f94062583a7539bd197268ddd5dc3cd6d21ceddb04473b3e").unwrap();
        let input = contract
            .function("validate")
            .unwrap()
            .encode_input(&vec![
                Token::Uint(e),
                Token::Bytes(n),
                Token::Bytes(message),
                Token::Bytes(sig),
            ])
            .unwrap();
        println!("abi input:{}", hex::encode(&input));
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
        println!("rsa validate return: {}", hex::encode(&run_result.return_data[..]));
        let ret = run_result.return_data.clone();
        println!("rsa validate return:{:?}", ret);
        let ret = i32::from_le_bytes(ret.get(..4).unwrap().try_into().unwrap());
        println!("rsa validate return:{}", ret);
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles("Rsa Validate", run_result.used_cycles, 820_000);
    }
}
