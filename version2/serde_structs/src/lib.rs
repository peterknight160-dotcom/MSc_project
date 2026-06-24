use serde::{Deserialize, Serialize};
use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_44, MlDsaKeyPair};


#[derive(Serialize, Deserialize, Debug)]
struct AuthenticationPackage {
    privatekey: Vec<u8>,
    publickey: Vec<u8>,
    client_id: String, // client_id not used by the receiver
}
#[derive(Serialize, Deserialize, Debug)]
struct PubKeyPackage {
    publickey: Vec<u8>,
    client_id: String, // Not used by the client.
}
#[derive(Serialize, Deserialize, Debug)]
struct SignedCipherText {
    ciphertext: Vec<u8>,
    signature: DilithiumSignature,
    payload: PayloadType
}
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey
}


