use crate::client::{self, Login, Offer};
use crate::server::{self, Policy};
use crate::{pack, tag, Cipher, Compression, Error, Mac, Random, Transport};

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// A Random that repeats `seq`.
fn cycle(seq: &'static [u8]) -> Random {
    let mut i = 0;
    Box::new(move |buf: &mut [u8]| {
        for b in buf {
            *b = seq[i % seq.len()];
            i += 1;
        }
    })
}

fn frame(opcode: u32, trans: u32, body: &[u8]) -> Vec<u8> {
    let size = (body.len() + 2) as u32;
    let mut f = Vec::new();
    for word in [opcode, trans, 0, size, size] {
        f.extend_from_slice(&word.to_be_bytes());
    }
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(body);
    f
}

fn gtkhx_offer(ciphers: Vec<Cipher>) -> Offer {
    Offer {
        ciphers,
        app_string: Some(b"hxnet 0.1.0".to_vec()),
        ..Offer::new(*b"GTKx")
    }
}

const WHO: Login<'static> = Login {
    login: b"guest",
    password: b"pw",
    name: b"me",
    icon: 414,
    version: 254,
    caps: 0x1f,
};

/// The bytes the client sent before this crate, the ones mhxd and Janus
/// were tested against: the handshake's two LOGINs and what each cipher
/// makes of the same transactions.
mod wire {
    use super::*;

    const STEP1: &str = "0000006b00000001000000000000005b0000005b00070069000100006a0001000e04002100030b484d41432d53484132353609484d41432d5348413108484d41432d4d44350e01000447544b780e02000b68786e657420302e312e300ec2000b000108424c4f57464953480e030000";
    const STEP2: &str = "0000006b00000002000000000000005900000059000700690014cc59246dc7d953f19cc62301eaf13e64962d5dc9006a00141e43ecb53e6d79bffe89235ed707c8553c817fa90ec1000b000108424c4f5746495348006600026d6500680002019e00a0000200fe01f00002001f";
    const BLOWFISH: &str = "610a4be63c9f0059f57614793975c8f27b84b4414f995db53951d4eb0cd5c1a9347002df9b4396522d3a9c32204f7c6f734b10ccb8093a5d5403d8ce1995534f6050e760a8ca6aa6710641ad26e3cf10a48262f892dfb4c19865c5cb2e688080bc4f003c6e04ca7628ee8b8d33722baef3d578dd5ed54e860f4153e8cc3e4193422dde1babb95da5e3fde1df946bcb3978749bc48e3d0229b4250d242a9d2aa78f946c7e24509109aa0fd127fd0fa37d72f601226772605c0788d9880d9016b478e3df8357bb33843a587e13bbbc9151dcb4382312b9222c54df51e384b196c8e7ab0ad4387770286439c18d0d2af963a0d6df413abd41207f168d2105a1f0d35b784ea6517d162ccc9dd57dec93553e9adfd97554d054c517b3e4a621d961ba5d1b74b2408490c2514695f98aac2586e11ec4d330b0be2c1fa711db184e1465bd85ef092f6dd2f1c8a40f7f832b8179df0105ecff9b1b7179a99f5eb4245d39340d2fdaf409c952a0acfd88aa325144646006";
    const AEAD: &str = "00000183d8d714cd39e720052cfd4380abdf6873c30713a840aa86fa1d24b031651529972d6502c32bd348e9015a8f2b01ba1aaea8f393f8f2afe3449178b86c1a157c4d5c91dda602678c0dbada5f2baf45d73c0374344eb5c1a88aa06ad80c1504958854a8dfbd30b16cd5b88f61aa97325054b6f87268be065e4c5250dc4d7709e805ba2763a7e54fa0912c2b478721f059dbe9bfc8ba18cc78cff1e830aa88de9f532d2b4aa285f0d91b944092e214d4dd98a272b3d242ab136fff579dc6b499ccf5989d5a3aa85c5d832b6efcb326532502ebf1b0d4db8498b391654c49dce7b064c8c1bd71e9bdb60bb92ee67ff82b3f7d9501cbe3a6084418cee1afdaece9ab21be5ec1868fe826f6ecc2bfbe7ce0b0cbb2255d80899ea134214194e49edf43e2b44e6bfa449efcc278e8d60ac46e1e5861ab28cb56ed8c5f6d23d46f3b22f397af105a444d0e0bc9f2cbeef656fbd95fa0d80860dcc0d1aafbc03510ff54d6b51e6452c34aeacfa3076b88500be04f1462e566a8a9d8f21e21efe1007c9a7c03e8e18e";

    /// A step-1 reply as mhxd sends it: HMAC-SHA1, the cipher, and the
    /// MAC's name as the login.
    fn reply(cipher: &[u8]) -> Vec<u8> {
        let sk: Vec<u8> = (0..64).collect();
        let mac = crate::alg::encode_list(&[b"HMAC-SHA1"]).unwrap();
        let cipher = crate::alg::encode_list(&[cipher]).unwrap();
        pack(
            0x0001_0000,
            1,
            &[
                (0x0069, b"HMAC-SHA1"),
                (tag::MAC_ALG, &mac),
                (tag::S_CIPHER_ALG, &cipher),
                (tag::SESSION_KEY, &sk),
            ],
        )
        .unwrap()
    }

    fn transactions() -> Vec<u8> {
        [
            frame(105, 3, b"hello"),
            frame(300, 4, b""),
            frame(105, 5, &[7; 300]),
        ]
        .concat()
    }

    #[test]
    fn the_handshake_is_byte_for_byte_what_it_was() {
        let offer = gtkhx_offer(vec![Cipher::Blowfish]);
        assert_eq!(hex(&client::step1(&offer, 1).unwrap()), STEP1);
        let est = client::step2(&offer, &reply(b"BLOWFISH"), &WHO, 2, cycle(&[0])).unwrap();
        assert_eq!(hex(&est.step2), STEP2);
    }

    #[test]
    fn blowfish_with_its_markers_is_byte_for_byte_what_it_was() {
        let offer = gtkhx_offer(vec![Cipher::Blowfish]);
        // Marks the first transaction with 5 rounds, not the second, the
        // third with 4.
        let random = cycle(&[0x20, 5 << 2, 0, 0, 0, 0, 0x70, 0, 0x18]);
        let mut t = client::step2(&offer, &reply(b"BLOWFISH"), &WHO, 2, random)
            .unwrap()
            .transport;
        assert_eq!(hex(&t.encode(&transactions()).unwrap()), BLOWFISH);
    }

    #[test]
    fn chacha20_poly1305_is_byte_for_byte_what_it_was() {
        let offer = gtkhx_offer(vec![Cipher::ChaCha20Poly1305]);
        let mut t = client::step2(&offer, &reply(b"CHACHA20-POLY1305"), &WHO, 2, cycle(&[0]))
            .unwrap()
            .transport;
        assert_eq!(hex(&t.encode(&transactions()).unwrap()), AEAD);
    }
}

/// A client and this crate's server, through the handshake to a
/// transport each.
fn handshake(
    offer: &Offer,
    policy: &Policy,
    password: &[u8],
) -> Result<(Transport, Transport, crate::Negotiated), Error> {
    let step1 = client::step1(offer, 1)?;
    assert!(server::is_step1(&step1));
    let (srv, reply) = server::answer(policy, &step1, [0x5a; 64], 1)?;
    // Marks about one transaction in five, either way.
    let random = || {
        cycle(&[
            0x20, 0x0c, 0, 0x10, 0, 0, 0x00, 0, 0, 0x70, 0, 0x30, 0x40, 0, 0,
        ])
    };
    let est = client::step2(offer, &reply, &WHO, 2, random())?;
    let step2 = srv.step2(&est.step2)?;
    assert!(step2.names(&srv, WHO.login));
    assert!(!step2.names(&srv, b"admin"));
    assert_eq!(
        (step2.name.as_slice(), step2.icon, step2.caps),
        (WHO.name, WHO.icon, WHO.caps)
    );
    let (server_side, negotiated) = srv.accept(&step2, password, random())?;
    assert_eq!(negotiated.cipher, est.negotiated.cipher);
    assert_eq!(negotiated.compression, est.negotiated.compression);
    Ok((est.transport, server_side, negotiated))
}

/// Transactions one way, cut into pieces `cut` bytes long on the wire.
fn carry(from: &mut Transport, to: &mut Transport, cut: usize) {
    let sent: Vec<Vec<u8>> = (0..40u32)
        .map(|i| frame(105, i, &vec![i as u8; (i as usize * 37) % 700]))
        .collect();
    let mut wire = Vec::new();
    for batch in sent.chunks(3) {
        wire.extend(from.encode(&batch.concat()).unwrap());
    }
    let mut got = Vec::new();
    for piece in wire.chunks(cut) {
        to.decode(piece, &mut got).unwrap();
    }
    assert_eq!(got, sent.concat());
    assert!(to.idle());
}

fn compressions() -> Vec<Option<Compression>> {
    let mut v = vec![None, Some(Compression::Gzip), Some(Compression::Lz4)];
    if cfg!(feature = "zstd") {
        v.push(Some(Compression::Zstd));
    }
    v
}

#[test]
fn every_transport_carries_both_ways_however_the_bytes_are_cut() {
    for cipher in [None, Some(Cipher::Blowfish), Some(Cipher::ChaCha20Poly1305)] {
        for compression in compressions() {
            let offer = Offer {
                ciphers: cipher.into_iter().collect(),
                compressions: compression.into_iter().collect(),
                ..Offer::new(*b"TEST")
            };
            let policy = Policy {
                macs: Mac::ALL.to_vec(),
                ciphers: vec![Cipher::Blowfish, Cipher::ChaCha20Poly1305],
                compressions: vec![Compression::Gzip, Compression::Lz4, Compression::Zstd],
                require_cipher: false,
            };
            let (mut c, mut s, n) = handshake(&offer, &policy, WHO.password).unwrap();
            assert_eq!((n.cipher, n.compression), (cipher, compression));
            assert_eq!(
                n.transfer_keys.is_some(),
                cipher == Some(Cipher::ChaCha20Poly1305)
            );
            for cut in [1, 7, 4096] {
                carry(&mut c, &mut s, cut);
                carry(&mut s, &mut c, cut);
            }
        }
    }
}

/// Compression goes on only when both sides want it, and the client's
/// choice of what to offer is the one that counts.
#[test]
fn compression_is_negotiated_only_when_both_sides_have_it() {
    let cases = [
        (
            vec![Compression::Gzip],
            vec![Compression::Gzip],
            Some(Compression::Gzip),
        ),
        (
            vec![Compression::Lz4, Compression::Gzip],
            vec![Compression::Gzip],
            Some(Compression::Gzip),
        ),
        (
            vec![Compression::Gzip, Compression::Lz4],
            vec![Compression::Lz4, Compression::Gzip],
            Some(Compression::Gzip),
        ),
        (vec![Compression::Gzip], vec![], None),
        (vec![], vec![Compression::Gzip], None),
    ];
    for (offered, has, want) in cases {
        let offer = Offer {
            ciphers: vec![Cipher::Blowfish],
            compressions: offered.clone(),
            ..Offer::new(*b"TEST")
        };
        let policy = Policy {
            macs: Mac::ALL.to_vec(),
            ciphers: vec![Cipher::Blowfish],
            compressions: has.clone(),
            require_cipher: true,
        };
        let (mut c, mut s, n) = handshake(&offer, &policy, WHO.password).unwrap();
        assert_eq!(
            n.compression, want,
            "offered {offered:?}, server has {has:?}"
        );
        carry(&mut c, &mut s, 100);
        carry(&mut s, &mut c, 100);
    }
}

/// A server that names a compression the client did not offer is not
/// answered with it, and the server, with no echo, runs none either.
#[test]
fn a_compression_nobody_asked_for_stays_off() {
    let offer = Offer::new(*b"TEST");
    let step1 = client::step1(&offer, 1).unwrap();
    let sk = [1u8; 64];
    let mac = crate::alg::encode_list(&[b"HMAC-MD5"]).unwrap();
    let gzip = crate::alg::encode_list(&[b"GZIP"]).unwrap();
    let reply = pack(
        0x0001_0000,
        1,
        &[
            (tag::MAC_ALG, &mac),
            (tag::S_COMPRESS_ALG, &gzip),
            (tag::SESSION_KEY, &sk),
        ],
    )
    .unwrap();
    assert!(server::is_step1(&step1));
    let est = client::step2(&offer, &reply, &WHO, 2, cycle(&[0])).unwrap();
    assert_eq!(est.negotiated.compression, None);
    assert!(crate::field(&est.step2, tag::S_COMPRESS_ALG).is_none());
}

#[test]
fn a_server_refuses_what_it_should() {
    let offer = Offer {
        ciphers: vec![Cipher::Blowfish],
        ..Offer::new(*b"TEST")
    };
    let policy = Policy {
        macs: Mac::ALL.to_vec(),
        ciphers: vec![Cipher::Blowfish],
        compressions: vec![],
        require_cipher: true,
    };
    assert!(matches!(
        handshake(&offer, &policy, b"not the password"),
        Err(Error::BadCredentials)
    ));
    let no_mac = Policy {
        macs: vec![],
        ..policy.clone()
    };
    assert!(matches!(
        handshake(&offer, &no_mac, WHO.password),
        Err(Error::Unsupported(_))
    ));
    let plaintext = Offer::new(*b"TEST");
    assert!(matches!(
        handshake(&plaintext, &policy, WHO.password),
        Err(Error::Unsupported(_))
    ));
    // A plain LOGIN is not a step 1.
    assert!(!server::is_step1(
        &pack(107, 1, &[(0x0069, &[0x9a])]).unwrap()
    ));
}

#[test]
fn a_damaged_stream_is_refused() {
    for cipher in [Cipher::Blowfish, Cipher::ChaCha20Poly1305] {
        let offer = Offer {
            ciphers: vec![cipher],
            ..Offer::new(*b"TEST")
        };
        let policy = Policy {
            macs: vec![Mac::Sha256],
            ciphers: vec![cipher],
            compressions: vec![],
            require_cipher: true,
        };
        let (mut c, mut s, _) = handshake(&offer, &policy, WHO.password).unwrap();
        let mut wire = c.encode(&frame(105, 1, b"hello")).unwrap();
        // The header's data size, enciphered, or a record's ciphertext.
        wire[17] ^= 0x80;
        assert!(s.decode(&wire, &mut Vec::new()).is_err(), "{cipher:?}");
    }
}

/// A server that requires a cipher refuses a step 2 that runs none, as it
/// would after a step-1 reply stripped of its cipher on the way.
#[test]
fn a_required_cipher_cannot_be_stripped_on_the_way() {
    let offer = Offer {
        ciphers: vec![Cipher::Blowfish],
        ..Offer::new(*b"TEST")
    };
    let policy = Policy {
        macs: Mac::ALL.to_vec(),
        ciphers: vec![Cipher::Blowfish],
        compressions: vec![],
        require_cipher: true,
    };
    let step1 = client::step1(&offer, 1).unwrap();
    let (srv, reply) = server::answer(&policy, &step1, [3; 64], 1).unwrap();
    let stripped: Vec<(u16, Vec<u8>)> = hxproto::wire::ChunkIter::over_message(&reply, reply.len())
        .filter(|c| c.tag != tag::S_CIPHER_ALG && c.tag != tag::C_CIPHER_ALG)
        .map(|c| (c.tag, c.data.to_vec()))
        .collect();
    let fields: Vec<(u16, &[u8])> = stripped.iter().map(|(t, d)| (*t, &d[..])).collect();
    let stripped = pack(0x0001_0000, 1, &fields).unwrap();
    let est = client::step2(&offer, &stripped, &WHO, 2, cycle(&[0])).unwrap();
    assert_eq!(est.negotiated.cipher, None);
    let step2 = srv.step2(&est.step2).unwrap();
    assert!(matches!(
        srv.accept(&step2, WHO.password, cycle(&[0])),
        Err(Error::Unsupported(_))
    ));
}

/// "NONE", an empty name and an empty list are all no compression; a
/// name nobody offered still fails the login.
#[test]
fn a_server_naming_no_compression_is_taken_at_its_word() {
    let offer = Offer {
        compressions: vec![Compression::Gzip],
        ..Offer::new(*b"TEST")
    };
    let mac = crate::alg::encode_list(&[b"HMAC-MD5"]).unwrap();
    let reply = |compression: &[u8]| {
        pack(
            0x0001_0000,
            1,
            &[
                (tag::MAC_ALG, &mac),
                (tag::S_COMPRESS_ALG, compression),
                (tag::SESSION_KEY, &[1; 64]),
            ],
        )
        .unwrap()
    };
    let none = [
        crate::alg::encode_list(&[b"NONE"]).unwrap(),
        crate::alg::encode_list(&[b""]).unwrap(),
        crate::alg::encode_list(&[]).unwrap(),
    ];
    for c in &none {
        let est = client::step2(&offer, &reply(c), &WHO, 2, cycle(&[0])).unwrap();
        assert_eq!(est.negotiated.compression, None, "{c:?}");
    }
    let lz4 = crate::alg::encode_list(&[b"LZ4"]).unwrap();
    assert!(client::step2(&offer, &reply(&lz4), &WHO, 2, cycle(&[0])).is_err());
}

/// A build without Zstandard neither offers it nor takes it.
#[cfg(not(feature = "zstd"))]
#[test]
fn zstd_is_neither_offered_nor_chosen_without_its_feature() {
    let offer = Offer {
        ciphers: vec![Cipher::ChaCha20Poly1305],
        compressions: vec![Compression::Zstd],
        ..Offer::new(*b"TEST")
    };
    let step1 = client::step1(&offer, 1).unwrap();
    assert!(crate::field(&step1, tag::C_COMPRESS_ALG).is_none());
    let both = crate::alg::encode_list(&[b"ZSTD", b"GZIP"]).unwrap();
    let macs = crate::field(&step1, tag::MAC_ALG).unwrap();
    let asks = pack(
        107,
        1,
        &[
            (0x0069, &[0]),
            (tag::MAC_ALG, macs),
            (tag::C_COMPRESS_ALG, &both),
        ],
    )
    .unwrap();
    let policy = Policy {
        macs: Mac::ALL.to_vec(),
        ciphers: vec![],
        compressions: vec![Compression::Zstd, Compression::Gzip],
        require_cipher: false,
    };
    let (_, reply) = server::answer(&policy, &asks, [3; 64], 1).unwrap();
    let gzip = crate::alg::encode_list(&[b"GZIP"]).unwrap();
    assert_eq!(crate::field(&reply, tag::S_COMPRESS_ALG), Some(&gzip[..]));
}

/// A cipher list that names no cipher is a broken reply, not plaintext: an
/// absent or zero-length field is how a server says none.
#[test]
fn a_cipher_list_naming_none_fails() {
    let offer = Offer {
        ciphers: vec![Cipher::Blowfish],
        ..Offer::new(*b"TEST")
    };
    let mac = crate::alg::encode_list(&[b"HMAC-MD5"]).unwrap();
    let empty = crate::alg::encode_list(&[]).unwrap();
    let reply = |cipher: &[u8]| {
        pack(
            0x0001_0000,
            1,
            &[
                (tag::MAC_ALG, &mac),
                (tag::S_CIPHER_ALG, cipher),
                (tag::SESSION_KEY, &[1; 64]),
            ],
        )
        .unwrap()
    };
    assert!(matches!(
        client::step2(&offer, &reply(&empty), &WHO, 2, cycle(&[0])),
        Err(Error::Malformed(_))
    ));
    let est = client::step2(&offer, &reply(&[]), &WHO, 2, cycle(&[0])).unwrap();
    assert_eq!(est.negotiated.cipher, None);
}
