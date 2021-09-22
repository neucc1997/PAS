#![feature(destructuring_assignment)]

#[macro_use]
extern crate serde_derive;
extern crate centipede;
extern crate curv;
extern crate serde;
extern crate bitcoin;
pub mod protocols;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::script::Script;
use protocols::aggsig::musig_three_rounds::*;

use protocols::aggsig::musig_three_rounds::KeyPair;
use protocols::aggsig::musig_three_rounds::KeyAgg;
use curv::elliptic::curves::traits::*;
use protocols::aggsig::musig_three_rounds::verify_partial;
#[allow(dead_code)]
type GE = curv::elliptic::curves::secp256_k1::GE;
#[allow(dead_code)]
type FE = curv::elliptic::curves::secp256_k1::FE;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}
use std::fmt;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}
impl std::error::Error for Error {}



// 多方场景下的多重签名+适配器签名验证
fn main() {
    let is_musig = true;
    let message: [u8; 4] = [79, 77, 69, 82];

    // round 0: generate signing keys
    let party1_key = KeyPair::create();
    let party2_key = KeyPair::create();
    let party3_key = KeyPair::create();
    let party4_key = KeyPair::create();
    let party5_key = KeyPair::create();

    // round 1: send commitments to ephemeral public keys (r, R)
    let party1_ephemeral_key = EphemeralKey::create();
    let party2_ephemeral_key = EphemeralKey::create();
    let party3_ephemeral_key = EphemeralKey::create();
    let party4_ephemeral_key = EphemeralKey::create();
    let party5_ephemeral_key = EphemeralKey::create();
    let party1_commitment = &party1_ephemeral_key.commitment;
    let party2_commitment = &party2_ephemeral_key.commitment;
    let party3_commitment = &party3_ephemeral_key.commitment;
    let party4_commitment = &party4_ephemeral_key.commitment;
    let party5_commitment = &party5_ephemeral_key.commitment;
    // secret t of party1
    let party1_sec_ephemeral_key = EphemeralKey::create();
    let party1_sec_commitment = &party1_sec_ephemeral_key.commitment;

    // round 2: send ephemeral public keys and check commitments
    // p1 release R1' and p2 test com(R1') = com(R1):
    assert!(EphemeralKey::test_com(
        &party1_ephemeral_key.keypair.public_key,
        &party1_ephemeral_key.blind_factor,
        party1_commitment
    ));
    // p1 release T' and others test com(T') = com(T):
    assert!(EphemeralKey::test_com(
        &party1_sec_ephemeral_key.keypair.public_key,
        &party1_sec_ephemeral_key.blind_factor,
        party1_sec_commitment
    ));
    assert!(EphemeralKey::test_com(
        &party2_ephemeral_key.keypair.public_key,
        &party2_ephemeral_key.blind_factor,
        party2_commitment
    ));
    assert!(EphemeralKey::test_com(
        &party3_ephemeral_key.keypair.public_key,
        &party3_ephemeral_key.blind_factor,
        party3_commitment
    ));
    assert!(EphemeralKey::test_com(
        &party4_ephemeral_key.keypair.public_key,
        &party4_ephemeral_key.blind_factor,
        party4_commitment
    ));
    assert!(EphemeralKey::test_com(
        &party5_ephemeral_key.keypair.public_key,
        &party5_ephemeral_key.blind_factor,
        party5_commitment
    ));

    // compute apk:
    let mut pks: Vec<GE> = Vec::new();
    pks.push(party1_key.public_key.clone());
    pks.push(party2_key.public_key.clone());
    pks.push(party3_key.public_key.clone());
    pks.push(party4_key.public_key.clone());
    pks.push(party5_key.public_key.clone());
    

    // 验证聚合公钥相等
    let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
    let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
    let party3_key_agg = KeyAgg::key_aggregation_n(&pks, 2);
    let party4_key_agg = KeyAgg::key_aggregation_n(&pks, 3);
    let party5_key_agg = KeyAgg::key_aggregation_n(&pks, 4);
    assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
    assert_eq!(party3_key_agg.apk, party4_key_agg.apk);

    // compute R' = R1+R2+T，验证略
    let mut common_tag = EphemeralKey::add_ephemeral_pub_keys(
        &party1_ephemeral_key.keypair.public_key,
        &party2_ephemeral_key.keypair.public_key,
    );
    common_tag = EphemeralKey::add_ephemeral_pub_keys(
        &common_tag,
        &party3_ephemeral_key.keypair.public_key,
    );
    common_tag = EphemeralKey::add_ephemeral_pub_keys(
        &common_tag,
        &party4_ephemeral_key.keypair.public_key,
    );
    common_tag = EphemeralKey::add_ephemeral_pub_keys(
        &common_tag,
        &party5_ephemeral_key.keypair.public_key,
    );
    common_tag = EphemeralKey::add_ephemeral_pub_keys(
        &common_tag,
        &party1_sec_ephemeral_key.keypair.public_key,
    );

    // compute c = H0(Rtag || apk || message)，验证略
    let common_c = EphemeralKey::hash_0(&common_tag, &party1_key_agg.apk, &message, is_musig);
    // println!("{}", party1_h_0 == party2_h_0);

    // compute partial signature s_i and send to the other party:
    // t, r, c, pk, H(apk,pk)
    // let s1 = EphemeralKey::sign_with_secret(
    //     &party1_sec_ephemeral_key,
    //     &party1_ephemeral_key,
    //     &common_c,
    //     &party1_key,
    //     &party1_key_agg.hash,
    // );
    let s1 = EphemeralKey::sign(
        &party1_ephemeral_key,
        &common_c,
        &party1_key,
        &party1_key_agg.hash,
    );
    let s2 = EphemeralKey::sign(
        &party2_ephemeral_key,
        &common_c,
        &party2_key,
        &party2_key_agg.hash,
    );
    let s3 = EphemeralKey::sign(
        &party3_ephemeral_key,
        &common_c,
        &party3_key,
        &party3_key_agg.hash,
    );
    let s4 = EphemeralKey::sign(
        &party4_ephemeral_key,
        &common_c,
        &party4_key,
        &party4_key_agg.hash,
    );
    let s5 = EphemeralKey::sign(
        &party5_ephemeral_key,
        &common_c,
        &party5_key,
        &party5_key_agg.hash,
    );

    // verify the partial signature corresponds to the secret t
    // parameters: s1, R1+T, c, a1, pk1
    // g^s1=R1*T*pk1^a1c
    // let r1 = party1_ephemeral_key.keypair.public_key;
    // let t = party1_sec_ephemeral_key.keypair.public_key;
    // // 先将两个Point相加，再取BigInt
    // let rt = (r1 + t).x_coor().unwrap();
    // println!(
    //     "Verify partial signature(with additional secret) {:?}",
    //     verify_partial(
    //         &ECScalar::from(&s1),
    //         &rt,
    //         &ECScalar::from(&common_c),
    //         &ECScalar::from(&party1_key_agg.hash),
    //         &party1_key.public_key
    //     )
    // );

    // verify the partial signature
    // parameters: s2, R2, c, a2, pk2
    // g^s2=R2*pk2^a2c
    let r2 = party2_ephemeral_key.keypair.public_key.x_coor().unwrap();
    println!(
        "Verify partial signature {:?}",
        verify_partial(
            &ECScalar::from(&s2),
            &r2,
            &ECScalar::from(&common_c),
            &ECScalar::from(&party2_key_agg.hash),
            &party2_key.public_key
        )
    );

    // signature s:
    let (mut r, mut s) = EphemeralKey::add_signature_parts(s1, &s2, &common_tag);
    (r, s) = EphemeralKey::add_signature_parts(s, &s3, &common_tag);
    (r, s) = EphemeralKey::add_signature_parts(s, &s4, &common_tag);
    (r, s) = EphemeralKey::add_signature_parts(s, &s5, &common_tag);

    // construct adaptor signature
    (r, s) = EphemeralKey::add_signature_parts_with_secret(s, &party1_sec_ephemeral_key, &common_tag);

    // verify:
    println!("Verify full signature {:?}", verify(&s, &r, &party1_key_agg.apk, &message, is_musig));

    println!("r={}  s={}", r, s);
}

// // 两方场景下的多重签名+适配器签名验证
// fn main() {
//     let is_musig = true;
//     let message: [u8; 4] = [79, 77, 69, 82];

//     // round 0: generate signing keys
//     let party1_key = KeyPair::create();
//     let party2_key = KeyPair::create();

//     // round 1: send commitments to ephemeral public keys (r, R)
//     let party1_ephemeral_key = EphemeralKey::create();
//     let party2_ephemeral_key = EphemeralKey::create();
//     let party1_commitment = &party1_ephemeral_key.commitment;
//     let party2_commitment = &party2_ephemeral_key.commitment;

//     // secret t of party1
//     let party1_sec_ephemeral_key = EphemeralKey::create();
//     let party1_sec_commitment = &party1_sec_ephemeral_key.commitment;

//     // round 2: send ephemeral public keys and check commitments
//     // p1 release R1' and p2 test com(R1') = com(R1):
//     assert!(EphemeralKey::test_com(
//         &party1_ephemeral_key.keypair.public_key,
//         &party1_ephemeral_key.blind_factor,
//         party1_commitment
//     ));

//     // p1 release T' and p2 test com(T') = com(T):
//     assert!(EphemeralKey::test_com(
//         &party1_sec_ephemeral_key.keypair.public_key,
//         &party1_sec_ephemeral_key.blind_factor,
//         party1_sec_commitment
//     ));

//     // p2 release R2' and p1 test com(R2') = com(R2):
//     assert!(EphemeralKey::test_com(
//         &party2_ephemeral_key.keypair.public_key,
//         &party2_ephemeral_key.blind_factor,
//         party2_commitment
//     ));

//     // compute apk:
//     let mut pks: Vec<GE> = Vec::new();
//     pks.push(party1_key.public_key.clone());
//     pks.push(party2_key.public_key.clone());
//     let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
//     let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
//     assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

//     // compute R' = R1+R2+T:
//     let mut party1_r_tag = EphemeralKey::add_ephemeral_pub_keys(
//         &party1_ephemeral_key.keypair.public_key,
//         &party2_ephemeral_key.keypair.public_key,
//     );
//     party1_r_tag = EphemeralKey::add_ephemeral_pub_keys(
//         &party1_r_tag,
//         &party1_sec_ephemeral_key.keypair.public_key,
//     );

//     let mut party2_r_tag = EphemeralKey::add_ephemeral_pub_keys(
//         &party1_ephemeral_key.keypair.public_key,
//         &party2_ephemeral_key.keypair.public_key,
//     );
//     party2_r_tag = EphemeralKey::add_ephemeral_pub_keys(
//         &party2_r_tag,
//         &party1_sec_ephemeral_key.keypair.public_key,
//     );

//     assert_eq!(party1_r_tag, party2_r_tag);

//     // compute c = H0(Rtag || apk || message)
//     let party1_h_0 = EphemeralKey::hash_0(&party1_r_tag, &party1_key_agg.apk, &message, is_musig);
//     let party2_h_0 = EphemeralKey::hash_0(&party2_r_tag, &party2_key_agg.apk, &message, is_musig);
//     println!("{}", party1_h_0 == party2_h_0);

//     // compute partial signature s_i and send to the other party:
//     let s1 = EphemeralKey::sign_with_secret(
//         &party1_sec_ephemeral_key,
//         &party1_ephemeral_key,
//         &party1_h_0,
//         &party1_key,
//         &party1_key_agg.hash,
//     );
//     let s2 = EphemeralKey::sign(
//         &party2_ephemeral_key,
//         &party2_h_0,
//         &party2_key,
//         &party2_key_agg.hash,
//     );

//     // verify the partial signature corresponds to the secret t
//     // parameters: s1, R1+T, c, a1, pk1
//     // g^s1=R1*T*pk1^a1c
//     let r1 = party1_ephemeral_key.keypair.public_key;
//     let t = party1_sec_ephemeral_key.keypair.public_key;
//     // 先将两个Point相加，再取BigInt
//     let rt = (r1+t).x_coor().unwrap();
//     println!(
//         "{:?}",
//         verify_partial(
//             &ECScalar::from(&s1),
//             &rt,
//             &ECScalar::from(&party1_h_0),
//             &ECScalar::from(&party1_key_agg.hash),
//             &party1_key.public_key
//         )
//     );

//     // verify the partial signature
//     // parameters: s2, R2, c, a2, pk2
//     // g^s2=R2*pk2^a2c
//     let r2 = party2_ephemeral_key.keypair.public_key.x_coor().unwrap();
//     println!(
//         "{:?}",
//         verify_partial(
//             &ECScalar::from(&s2),
//             &r2,
//             &ECScalar::from(&party2_h_0),
//             &ECScalar::from(&party2_key_agg.hash),
//             &party2_key.public_key
//         )
//     );

//     // signature s:
//     let (r, s) = EphemeralKey::add_signature_parts(s1, &s2, &party1_r_tag);

//     // verify:
//     assert!(verify(&s, &r, &party1_key_agg.apk, &message, is_musig,).is_ok());

//     println!("r={}  s={}", r, s);
// }

// // 多重签名验证
// fn main() {
//     let is_musig = true;
//     let message: [u8; 4] = [79, 77, 69, 82];

//     // round 0: generate signing keys
//     let party1_key = KeyPair::create();
//     let party2_key = KeyPair::create();

//     // round 1: send commitments to ephemeral public keys
//     let party1_ephemeral_key = EphemeralKey::create();
//     let party2_ephemeral_key = EphemeralKey::create();
//     let party1_commitment = &party1_ephemeral_key.commitment;
//     let party2_commitment = &party2_ephemeral_key.commitment;

//     // round 2: send ephemeral public keys and check commitments
//     // p1 release R1' and p2 test com(R1') = com(R1):
//     assert!(EphemeralKey::test_com(
//         &party2_ephemeral_key.keypair.public_key,
//         &party2_ephemeral_key.blind_factor,
//         party2_commitment
//     ));
//     // p2 release R2' and p1 test com(R2') = com(R2):
//     assert!(EphemeralKey::test_com(
//         &party1_ephemeral_key.keypair.public_key,
//         &party1_ephemeral_key.blind_factor,
//         party1_commitment
//     ));

//     // compute apk:
//     let mut pks: Vec<GE> = Vec::new();
//     pks.push(party1_key.public_key.clone());
//     pks.push(party2_key.public_key.clone());
//     let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
//     let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
//     assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

//     // compute R' = R1+R2:
//     let party1_r_tag = EphemeralKey::add_ephemeral_pub_keys(
//         &party1_ephemeral_key.keypair.public_key,
//         &party2_ephemeral_key.keypair.public_key,
//     );

//     let party2_r_tag = EphemeralKey::add_ephemeral_pub_keys(
//         &party1_ephemeral_key.keypair.public_key,
//         &party2_ephemeral_key.keypair.public_key,
//     );

//     assert_eq!(party1_r_tag, party2_r_tag);

//     // compute c = H0(Rtag || apk || message)
//     let party1_h_0 = EphemeralKey::hash_0(&party1_r_tag, &party1_key_agg.apk, &message, is_musig);
//     let party2_h_0 = EphemeralKey::hash_0(&party2_r_tag, &party2_key_agg.apk, &message, is_musig);
//     assert_eq!(party1_h_0, party2_h_0);

//     // compute partial signature s_i and send to the other party:
//     let s1 = EphemeralKey::sign(
//         &party1_ephemeral_key,
//         &party1_h_0,
//         &party1_key,
//         &party1_key_agg.hash,
//     );
//     let s2 = EphemeralKey::sign(
//         &party2_ephemeral_key,
//         &party2_h_0,
//         &party2_key,
//         &party2_key_agg.hash,
//     );

//     let r = party1_ephemeral_key.keypair.public_key.x_coor().unwrap();

//     // verify the partial signature
//     // parameters: s1, R1, c, a1, pk1
//     // g^s1=R1*pk1^a1c
//     println!(
//         "{:?}",
//         verify_partial(
//             &ECScalar::from(&s1),
//             &r,
//             &ECScalar::from(&party1_h_0),
//             &ECScalar::from(&party1_key_agg.hash),
//             &party1_key.public_key
//         )
//     );

//     // signature s:
//     let (r, s) = EphemeralKey::add_signature_parts(s1, &s2, &party1_r_tag);

//     // verify:
//     assert!(verify(&s, &r, &party1_key_agg.apk, &message, is_musig,).is_ok());

//     println!("r={}  s={}", r, s);
// }
fn generateScript_0(cltv_time:u32,pk:GE,pk_agg1:Vec<u8>)->Script{
    Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_int(cltv_time as i64)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        // .push_opcode(opcodes::all::OP_VERIFY)
        .push_slice(&pk.pk_to_key_slice())
        // .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_slice(&pk_agg1)
        .push_opcode(opcodes::all::OP_ENDIF)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}
fn generateScript_1(cltv_time:u32,pk:GE,pk_agg1:Vec<u8>,pk_agg2:Vec<u8>)->Script{
    Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_int(cltv_time as i64)
        .push_opcode(opcodes::all::OP_CLTV)
        // .push_opcode(opcodes::all::OP_VERIFY)
        .push_slice(&pk.pk_to_key_slice())
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_int(1)
        .push_slice(&pk_agg1)
        .push_slice(&pk_agg2)
        .push_int(2)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script()
}
#[derive(Debug)]
struct Node{
    index:u32,  //节点序号
    keypair:KeyPair,  //公私钥对
    ephemeral_key:EphemeralKey, 
    sec_ephemeral_key:EphemeralKey  
}
impl Node {
    fn create(num: u32) -> Node {        
        let node_keypair=Node{
                 index : num,
                 keypair : KeyPair::create(),
                 ephemeral_key : EphemeralKey::create(),
                 sec_ephemeral_key : EphemeralKey::create()
             };
         return node_keypair;
    }
    fn checkCommitment(pubkey:GE,blind_factor:BigInt,commitment:BigInt)->bool{
        let is_correct=EphemeralKey::test_com(
            &pubkey,
            &blind_factor,
            &commitment
        )
        return is_correct;
    }
    fn broadcast(pubkey:GE,commitment:BigInt){
        //broadcast commit
    }
    fn computApk(num:u32,sum:u32, pubkey_list:Vec<GE>)->(Vec<KeyAgg>,Vec<BigInt>,Vec<BigInt>){
        let pks_0:Vec<GE>=Vec::new();
        let pks_1:Vec<GE>=Vec::new();
        let agg_key_list:Vec<KeyAgg>=Vec::new();
        let common_c_list:Vec<BigInt>=Vec::new();
        let common_tag_list:Vec<BigInt>=Vec::new();
        let is_musig = true;
        let message: [u8; 4] = [79, 77, 69, 82];
        if num==1 {
            pks_0.push(pubkey_list[0].clone());
            pks_0.push(pubkey_list[1].clone());
            let agg_key=KeyAgg::key_aggregation_n(&pks_0, 0);
            agg_key_list.push(agg_key.clone());

            let common_tag= EphemeralKey::add_ephemeral_pub_keys(
                &pubkey_list[0].clone(),
                &pubkey_list[1].clone(),
            );
            common_tag_list.push(common_tag.clone());

            let common_c = EphemeralKey::hash_0(&common_tag, &agg_key.apk, &message, is_musig);
            common_c_list.push(common_c.clone());
            // let s = EphemeralKey::sign(
            //     &party1_ephemeral_key,
            //     &common_c,
            //     &party1_key,
            //     &party1_key_agg.hash,
            // );
        }
        else if num==2 {
            pks_0.push(pubkey_list[0].clone());
            pks_0.push(pubkey_list[1].clone());
            pks_0.push(pubkey_list[2].clone());
            let agg_key=KeyAgg::key_aggregation_n(&pks_0, 0);
            agg_key_list.push(agg_key.clone());

            let mut common_tag= EphemeralKey::add_ephemeral_pub_keys(
                &pubkey_list[0].clone(),
                &pubkey_list[1].clone(),
            );
            common_tag= EphemeralKey::add_ephemeral_pub_keys(
                &common_tag,
                &pubkey_list[2].clone()
            );
            common_tag_list.push(common_tag.clone());

            let common_c = EphemeralKey::hash_0(&common_tag, &agg_key.apk, &message, is_musig);
            common_c_list.push(common_c.clone());
        }
        else if num==sum {
            pks_0.push(pubkey_list[0].clone());
            pks_0.push(pubkey_list[num-2].clone());
            pks_0.push(pubkey_list[num-1].clone());
            let agg_key_0=KeyAgg::key_aggregation_n(&pks_0, 0);
            agg_key_list.push(agg_key_0.clone());

            let mut common_tag_0= EphemeralKey::add_ephemeral_pub_keys(
                &pubkey_list[0].clone(),
                &pubkey_list[num-2].clone(),
            );
            common_tag_0= EphemeralKey::add_ephemeral_pub_keys(
                &common_tag_0,
                &pubkey_list[num-1].clone()
            );
            common_tag_list.push(common_tag_0.clone());
            let common_c_0 = EphemeralKey::hash_0(&common_tag_0, &agg_key.apk, &message, is_musig);
            common_c_list.push(common_c_0.clone());

            let mut i=0;
            while i<num-2{
                pks_1.push(pubkey_list[i].clone());
                i+=1;
            }
            pks_1.push(pubkey_list[num-1].clone());
            let agg_key_1=KeyAgg::key_aggregation_n(&pks_1, 0);
            agg_key_list.push(agg_key_1.clone());

            let mut j=0;
            let mut common_tag_1= EphemeralKey::add_ephemeral_pub_keys(
                &pubkey_list[j].clone(),
                &pubkey_list[j+1].clone(),
            );
            while j<num-3 {
                j+=1;
                common_tag_1= EphemeralKey::add_ephemeral_pub_keys(
                    &common_tag_1,
                    &pubkey_list[j+1].clone()
                );
            }
            common_tag_list.push(common_tag_1.clone());
            let common_c_1 = EphemeralKey::hash_0(&common_tag_1, &agg_key.apk, &message, is_musig);
            common_c_list.push(common_c_1.clone());
        }
        else {
            // let mut i=num-2;
            // while i<num {
            //     pks_0.push(pubkey_list[i].clone());
            //     i+=1;
            // }
            pks_0.push(pubkey_list[num-2].clone());
            pks_0.push(pubkey_list[num-1].clone());
            pks_0.push(pubkey_list[num].clone());
            let agg_key_0=KeyAgg::key_aggregation_n(&pks_0, 0);
            agg_key_list.push(agg_key_0.clone());

            let mut common_tag_0= EphemeralKey::add_ephemeral_pub_keys(
                &pubkey_list[num-2].clone(),
                &pubkey_list[num-1].clone(),
            );
            common_tag_0= EphemeralKey::add_ephemeral_pub_keys(
                &common_tag_0,
                &pubkey_list[num].clone()
            );
            common_tag_list.push(common_tag_0.clone());
            let common_c_0 = EphemeralKey::hash_0(&common_tag_0, &agg_key.apk, &message, is_musig);
            common_c_list.push(common_c_0.clone());
            
            let mut j=0;
            while j<num-2{
                pks_1.push(pubkey_list[j].clone());
                j+=1;
            }
            pks_1.push(pubkey_list[num-1].clone());
            pks_1.push(pubkey_list[num].clone());
            let agg_key_1=KeyAgg::key_aggregation_n(&pks_1, 0);
            agg_key_list.push(agg_key_1.clone());

            let mut i=0;
            let mut common_tag_1= EphemeralKey::add_ephemeral_pub_keys(
                &pubkey_list[i].clone(),
                &pubkey_list[i+1].clone(),
            );
            while i<num-3 {
                i+=1;
                common_tag_1= EphemeralKey::add_ephemeral_pub_keys(
                    &common_tag_1,
                    &pubkey_list[i+1].clone()
                );
            }
            common_tag_1= EphemeralKey::add_ephemeral_pub_keys(
                &common_tag_1,
                &pubkey_list[i+2].clone()
            );
            common_tag_1= EphemeralKey::add_ephemeral_pub_keys(
                &common_tag_1,
                &pubkey_list[i+3].clone()
            );
            common_tag_list.push(common_tag_1.clone());
            let common_c_1 = EphemeralKey::hash_0(&common_tag_1, &agg_key.apk, &message, is_musig);
            common_c_list.push(common_c_1.clone());
        }
        return (agg_key_list,common_c_list,common_tag_list);
    }
    fn sign(node:Node,key_agg:KeyAgg,common_c:BigInt)->BigInt{
        EphemeralKey::sign(
            &node.ephemeral_key,
            &common_c,
            &node.keypair,
            &key_agg.hash,
        )
    }
    fn partialVerifySig(sig:BigInt,pubkey_0:GE,common_c:BigInt,key_agg:KeyAgg,pubkey_1:GE){
        let r=pubkey_0.x_coor().unwrap();
        println!(
            "Verify partial signature {:?}",
            verify_partial(
                &ECScalar::from(&sig),
                &r,
                &ECScalar::from(&common_c),
                &ECScalar::from(&key_agg.hash),
                &pubkey_1
            )
        );
    }
    fn signAgg(node:Node,sig_list:Vec<BigInt>,common_tag:BigInt)->BigInt{
        //let sig_agg_list:Vec<BigInt>=Vec::new();
        
        let (mut r, mut s) = EphemeralKey::add_signature_parts(sig_list[0], &sig_list[1], &common_tag);
        if sig_list.len()>2 {
            let mut i=2;
            while i<sig_list.len() {
                (r, s) = EphemeralKey::add_signature_parts(s, &sig_list[i], &common_tag);
                i+=1;
            }
            (r, s) = EphemeralKey::add_signature_parts_with_secret(s, &node.sec_ephemeral_key, &common_tag);
        }
        return s;             
    }
    
    }
    
}

#[test]
fn test_main(){
    println!("{}","woshiceshi");
    let node_1=Node::create(1);
    let commitment=&node_1.sec_ephemeral_key.commitment;
    println!("{:?}",node_1);
    println!("{:?}",commitment);
    //node_1 broadcast the commitment


}
