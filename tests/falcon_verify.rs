//! Falcon verification against a fixed vector.
//!
//! Verification is integer arithmetic only, so it is available wherever this crate builds: with
//! the `falcon-verify` feature alone, and on targets where Falcon key generation and signing are
//! not built (see `sign::FALCON_SIGNING_AVAILABLE`). These tests need no signing.
//!
//! The vector was produced with falcon-rs 0.2.3, Falcon-512, no domain separation:
//! key = `FnDsaKeyPair::generate_deterministic(b"paraxiom-pqc falcon-512 test vector key", 9)`,
//! signature = `key.sign_deterministic(MSG, b"paraxiom-pqc falcon-512 test vector signature",
//! &DomainSeparation::None)`, which is the 809-byte constant-time encoding that `sign::sign` also
//! produces.
#![cfg(any(feature = "sign", feature = "falcon-verify"))]

use paraxiom_pqc::falcon;

const MSG: &[u8] = b"paraxiom-pqc falcon verification vector";

const PUBLIC_KEY: &str = concat!(
    "0996b046a91d138609a24523f5700068dcfac222a049ac1546e87c6ea0a0147c0446ccd110a5a717d903cfa3",
    "39c5e519cab63b355dd5b2a97248d9cc5214c192984ede6a546c538e42c838066f481fae25d638536f6ae11c",
    "820523b2a9eeddc160208d6d795d09c4e3d494ce81ba75a5ba4409a09886484470d24c582a686649b47fd5d5",
    "dd4861709843da55340218b3b23ca8b65ae5f3282587dc0481e6e8aead48b958201b5ee423b784ab93588966",
    "6da4ef8b26572e553e4bf0221deb2a62ff4249cec32364ec42c9a9b4ada8a674a08d04a5de5027070be8198e",
    "8505a148ae57a9079299aabc7256d960e0eda7b8400d23e925492372aec9a2a721a462bac4ef60f794453af3",
    "11915cb509db9755051749c438ca105abc9b856f2b715f91bbf006a91e23f47f057d0aedc33c98a851c5ac17",
    "837ce46daae149bfbf4a4f42321086a032596896a06cbbce6379b20c5e246600c67e99d1aa69608574e30695",
    "f47d488821564c75280b37981435d25bb7e74d7270f0f1eb4604a931825272785afd5379c71b24ad032b3ea4",
    "ab950fbd37d28d56915c47bc114aa814e37f06529aeb8a63b3763630b57569d27df1ada2ef82913078aea880",
    "10deb21ecbc0148a1bad3e2bdba7045105296246834e446aa8be713b84820a504407a11c123bf21ca8cb54ae",
    "b018c310fc601b7a1e3ac3681ba95b3891627ada0e8fc938856ba4c58a59abc9ae8d0baca24b293742398156",
    "aa81d88ba4b33662b368db2b7870cc6025cfd8b26021299a1778585d17f37905bb9200b0f103a7c9ac40a0c8",
    "f1918d873a7338728ad13768d4744b045baea633c72be2776a5db3346915c5634da6562a2e817742097a7255",
    "990b5c7df5f58af14391ce4276ada4296c2bb3dfc65f3ca52cd0de64a83cf10f874d102f51b54aa73923394c",
    "91dfea2fc16f45e085a62e1c608ea1f4319f5ec72dca0d93f55f2e62a90473f88909ab24c4321ddc74897e01",
    "b292e659706963140e814e7b695025884c520aa5d18af7845e8f4db60aca1885b9bef1c756004c5196a1e9f8",
    "eac8932495d0ca89985b4a9c8b5781cd8bc1ecd1e893910a70204ab14adb2e0007f455248e2e22d950a74fea",
    "52127306f4e59744229c75c40bbabffad15aa30362721607d362c9d33305e5183dc77d57cd934305509857b4",
    "63a89ce50929e9bc0582ed311005c6369521a2103eff88beed15b14e3fe3a3946fb372f997c8ea541b3e35aa",
    "daed77054e6cd90f868441612a0870273b",
);

const SIGNATURE: &str = concat!(
    "5986d1e6ec912fa65bd13de4d3b8322c24f0e3ec39e413f43b2c346d85c61544ebbe25c64c3ee3f6a6ee301c",
    "f45056f4602a0e1f9af3ef7608dfcbfbff9807d1270ba0d50aefa5fc6fa9ffcf68fc0fcc01107419dea201a1",
    "030450e002b04004e071ff5f970d2136f52f9bff6038061fc9ee9fd8fdc0f3f75fff18404304ef5b00008fff",
    "10d9ff5fd6fcef0f085f3bfcef960c00360db056f0802b0bc0e0fa1016eb702a03aefaf1f063fbd02509201c",
    "057f8201b02d01502a041ffcf76f26f9f039fbafe6ea10521ad078ea1fe4f89ee7f4403b096071f70fd7ffa0",
    "48fbcf86f47fe900efede9001c018f2ff6ffbaf64061eddf9cf69055f5c01eec1f5ffd506803df77052ee9ef",
    "40d5047faf0720a0fecf2cf870befc60f804ef7af8b0ec03e09400101af3c150105eedf89f2e0dbfca072049",
    "09d05b0c90f7f1ef52fedfbb00cfafffafb00cd019fbc0650530d8f9af32037025012ffef1efbbe7c03c05b0",
    "3f00d05b1600adf47fe2fe4ed0fb9121088011f25007045f2207002400dfe8fe3084f88fa809302c06307b01",
    "106cfe111c065eb8fd0fdcf840570bbf79080f6d0d5083086eddebd03aef1025fa70df0bd03303801ded810b",
    "0d1ff8f87e14f6907907d016fbcede018071f01f4ef0afbbf36fcafe50e5f68fefeddf180be047fa2fa705df",
    "5a0bd0def25f4af6cea3fe3f38fef031059f6aff109a0b4f860a4063f9005f013faf036f90076fe10bbfccf4",
    "9fc6fd5f2bfa100a18525e0eef500650500b900cff1eb90a000f03b0d7fec02ce2b007fc4fa0f280050b4fd2",
    "00b00a018ff0edbf5b0a6079032fe4fc1ff8fb6f42efd06cef8059f88ffe036067fd8094132f8e09c091049f",
    "a2feaf9cf6aff2004fba023f1c007f9302cfe1f59fb309d081f0a09c099fd10c0fc1fe4179031fd5f54fdc13",
    "403dfdc0a4039fca093f96f060d3f4dfeafaf010008f540f505506b05ef8109d16817a038fdb016fcb016fea",
    "0060fe086017f88f7cfbf0200aff0bf93f8df3912df98f8b12af3af8101c03504c0ecf41f7af68f97ed5f89f",
    "88f37017fc4f57e98f0ef62055ff5fa6086fde13dff20170f603cf850570fef2ff9ef3bfb9f6df2ef7ffaaf4",
    "803303fef4150180f52f6f0c0ee1ff7f45",
);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn fixed_vector_verifies() {
    let (pk, sig) = (unhex(PUBLIC_KEY), unhex(SIGNATURE));
    assert_eq!((pk.len(), sig.len()), (897, 809));
    assert!(falcon::verify(&pk, MSG, &sig));
}

#[test]
fn fixed_vector_rejects_changes() {
    let (pk, sig) = (unhex(PUBLIC_KEY), unhex(SIGNATURE));
    assert!(!falcon::verify(&pk, b"paraxiom-pqc falcon verification vectoR", &sig));

    let mut bad_sig = sig.clone();
    bad_sig[400] ^= 0x01;
    assert!(!falcon::verify(&pk, MSG, &bad_sig));

    let mut bad_pk = pk.clone();
    bad_pk[500] ^= 0x01;
    assert!(!falcon::verify(&bad_pk, MSG, &sig));
}

/// `sign::verify` goes through the same function and accepts the same signature.
#[cfg(feature = "sign")]
#[test]
fn sign_verify_accepts_the_fixed_vector() {
    use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, VerificationKey};

    let vk = VerificationKey {
        algorithm: SignAlgorithm::Falcon512,
        bytes: unhex(PUBLIC_KEY),
    };
    let sig = Signature {
        algorithm: SignAlgorithm::Falcon512,
        bytes: unhex(SIGNATURE),
    };
    assert!(sign::verify(&vk, MSG, &sig).unwrap());
}
