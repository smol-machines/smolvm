use ssh_key::{Algorithm, PrivateKey};

use crate::keys::pkcs8::{decode_pkcs8, encode_pkcs8_encrypted};

use super::decode_secret_key;

#[test]
fn test_ec_private_key() {
    let key = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBNK0jwKqqf8zkM+Z2l++9r8bzdTS/XCoB4N1J07dPxpByyJyGbhvIy
1kLvY2gIvlmgBwYFK4EEACKhZANiAAQvPxAK2RhvH/k5inDa9oMxUZPvvb9fq8G3
9dKW1tS+ywhejnKeu/48HXAXgx2g6qMJjEPpcTy/DaYm12r3GTaRzOBQmxSItStk
lpQg5vf23Fc9fFrQ9AnQKrb1dgTkoxQ=
-----END EC PRIVATE KEY-----"#;
    decode_secret_key(key, None).unwrap();
}

#[test]
fn test_pkcs8_roundtrip() {
    let password = b"SomePassword";
    let original_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();

    let encrypted = encode_pkcs8_encrypted(password, 10, &original_key).unwrap();
    let decrypted = decode_pkcs8(&encrypted, Some(password)).unwrap();
    assert_eq!(decrypted, original_key);
}

#[test]
fn test_ec_private_key_with_full_domain_params() {
    // This key uses full EC domain parameters instead of a named curve OID.
    // Generated with: openssl ecparam -name prime256v1 -genkey -param_enc explicit -noout
    // The sec1 crate cannot parse this format; our fallback parser handles it.
    let key = "-----BEGIN EC PRIVATE KEY-----\n\
MIIBaAIBAQQguoBiuFhw88aF2jBBK9zZAxFL3fTXmSnjUt2usONDS+SggfowgfcC\n\
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////\n\
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr\n\
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE\n\
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W\n\
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8\n\
YyVRAgEBoUQDQgAEqZqnpFc/+9yfQh7B/sx5dms/sccAtE+PoGTqAa4y399K1S0H\n\
b6KBhA+L9No0qBbsdpwaMewJChyf5AIft0Un3A==\n\
-----END EC PRIVATE KEY-----";
    let result = decode_secret_key(key, None);
    assert!(result.is_ok(), "Failed to parse EC key with full domain params: {:?}", result.err());
    let pk = result.unwrap();
    assert_eq!(pk.algorithm(), Algorithm::Ecdsa {
        curve: ssh_key::EcdsaCurve::NistP256,
    });
}

#[test]
fn test_ec_p521_private_key_with_full_domain_params() {
    // P-521 key with full EC domain parameters (not named curve OID).
    // Generated with: openssl ecparam -name secp521r1 -genkey -param_enc explicit -noout
    let key = "-----BEGIN EC PRIVATE KEY-----\n\
MIICngIBAQRCAH2esSsV6PlGdsc5TekzHNtyj0vhHfok5t0UCXu08hL3ZYqe7JKP\n\
EjUiuV0NWoo++Zy3juTEB+nssQhOBd4DOBpmoIIBxzCCAcMCAQEwTQYHKoZIzj0B\n\
AQJCAf//////////////////////////////////////////////////////////\n\
////////////////////////////MIGfBEIB////////////////////////////\n\
//////////////////////////////////////////////////////////wEQgBR\n\
lT65YY4cmh+SmiGgtoVA7qLacluZsxXzuLSJkY7xCeFWGTlR7H6TexZSwL07sb8H\n\
NXPfiD0sNPHvRR/Ua1A/AAMVANCeiAApHLhTlsxnFzkyhKqg2mS6BIGFBADGhY4G\n\
twQE6c2ePstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0iz\n\
wYVqQpv5fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX\n\
7nKZXvQmQMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////\n\
////////////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6R\n\
OGQJAgEBoYGJA4GGAAQAtGyQsquetaPetft29sZ1SxWcegQj59V3cSLSaQYpjesA\n\
ERfIfoSaPbVtCanBcJ4xIPvxaarrGhWCj1B3mjmSDv4B1DDMQiD6jggxZrzg+kRC\n\
vVH8f9/FHwjQjBWEtctiQzPShusqnD5I3hTBBbX/qh0XaLcLMz0bA0o/HHQ+0xUw\n\
Aak=\n\
-----END EC PRIVATE KEY-----";
    let result = decode_secret_key(key, None);
    assert!(result.is_ok(), "Failed to parse P-521 key with full domain params: {:?}", result.err());
    let pk = result.unwrap();
    assert_eq!(pk.algorithm(), Algorithm::Ecdsa {
        curve: ssh_key::EcdsaCurve::NistP521,
    });
}

#[test]
fn test_ec_malformed_der_returns_error() {
    // Completely invalid data — not valid SEC1 or PKCS#8
    let result = decode_secret_key("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----", None);
    assert!(result.is_err(), "Should fail on malformed DER");

    // Truncated SEC1 key
    let result = decode_secret_key("-----BEGIN EC PRIVATE KEY-----\nMIIBaAIBAQQg\n-----END EC PRIVATE KEY-----", None);
    assert!(result.is_err(), "Should fail on truncated key");
}
