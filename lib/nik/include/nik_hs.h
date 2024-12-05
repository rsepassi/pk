#include "crypto.h"

#define NIK_CHAIN_SZ     32
#define NIK_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b"

// Status/error codes
typedef enum {
  NIK_OK = 0,
  NIK_Err,
  NIK_ErrFailedVerify,
} NIK_Status;

// Keys for establishing a session with bob
typedef struct {
  CryptoKxPK*   pk;
  CryptoKxSK*   sk;
  CryptoKxPK*   bob;
  CryptoBoxKey* psk;
} NIK_Keys;

// Alice sends Bob Handshake1
typedef struct __attribute__((packed)) {
  CryptoKxPK    ephemeral;  // plaintext
  CryptoKxPK    statik;     // encrypted
  CryptoAuthTag tag;
} NIK_Handshake1;

// Bob responds with Handshake2
typedef struct __attribute__((packed)) {
  CryptoKxPK    ephemeral;  // plaintext
  CryptoAuthTag tag;
} NIK_Handshake2;

// State kept during a handshake
typedef struct {
  NIK_Keys                         keys;
  u8                               chaining_key[NIK_CHAIN_SZ];
  crypto_generichash_blake2b_state hash;
  CryptoKxSK                       ephemeral_sk;
  CryptoKxPK                       ephemeral_pk;
} NIK_HandshakeState;

// Final shared secret
typedef struct {
  u8 secret[NIK_CHAIN_SZ];
} NIK_SharedSecret;

// Alice initiates a handshake to Bob
// hs goes to Bob
NIK_Status nik_handshake_start(NIK_HandshakeState* state, const NIK_Keys keys,
                               NIK_Handshake1* hs);

// Bob finalizes the handshake and responds with NIK_Handshake2
// hs1 will have statik decrypted in-place
// hs2 goes to Alice
NIK_Status nik_handshake_responder_finish(NIK_HandshakeState* state,
                                          const NIK_Keys      keys,
                                          NIK_Handshake1*     hs1,
                                          NIK_Handshake2*     hs2,
                                          NIK_SharedSecret*   secret);

// Alice finalizes the handshake based on Bob's response
NIK_Status nik_handshake_finish(NIK_HandshakeState*   state,
                                const NIK_Handshake2* hs,
                                NIK_SharedSecret*     secret);
