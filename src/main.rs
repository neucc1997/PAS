#![feature(destructuring_assignment)]

#[macro_use]
extern crate serde_derive;
extern crate centipede;
extern crate curv;
extern crate serde;
pub mod protocols;

use protocols::aggsig::musig_three_rounds::*;
// use protocols::aggsig::musig_three_rounds::KeyPair;
// use protocols::aggsig::musig_three_rounds::KeyAgg;
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
    let (_, mut s) = EphemeralKey::add_signature_parts(s1, &s2, &common_tag);
    (_, s) = EphemeralKey::add_signature_parts(s, &s3, &common_tag);
    (_, s) = EphemeralKey::add_signature_parts(s, &s4, &common_tag);
    (_, s) = EphemeralKey::add_signature_parts(s, &s5, &common_tag);

    // construct adaptor signature
    let (r, s) = EphemeralKey::add_signature_parts_with_secret(s, &party1_sec_ephemeral_key, &common_tag);

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
