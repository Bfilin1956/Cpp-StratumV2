//
// Created by filin on 12/30/25.
//
#include <vector>
#include <cstdint>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_schnorrsig.h>

#include <stdexcept>

using Bytes = std::vector<uint8_t>;

struct CipherState {};
struct Keys {
    unsigned char secret_key[32];
    secp256k1_pubkey pubKey;
    unsigned char ellswift_pubkey_e[64];
    unsigned char ellswift_pubkey_re[64];
    Bytes ck;     // chaining key
    Bytes h;      // handshake hash
    CipherState cs;
    unsigned char ecdh_x[32];
    unsigned char temp_k[32];
};

Bytes tagged_hash(Bytes &a, Bytes &b, Bytes &c);


Bytes ECDH_Initiator(secp256k1_context* ctx, Keys &keys) {
    Bytes secret(32);
    int ret = secp256k1_ellswift_xdh(ctx, secret.data(), keys.ellswift_pubkey_e, keys.ellswift_pubkey_re,
        keys.secret_key, 0, secp256k1_ellswift_xdh_hash_function_bip324, nullptr);
    if (!ret) {
        throw std::runtime_error("ECDH failed");
    }
    Bytes temp1(keys.ellswift_pubkey_e, keys.ellswift_pubkey_e+64);
    Bytes temp2(keys.ellswift_pubkey_re, keys.ellswift_pubkey_re+64);
    return tagged_hash(temp1 ,temp2,secret);
}
Bytes ECDH_Initiator(secp256k1_context* ctx, Keys &keys, Bytes &their_ellswift, Bytes &our_ellswift) {
    bool initiating{true};
    Bytes secret(32);
    int ret = secp256k1_ellswift_xdh(ctx,secret.data(), initiating ? our_ellswift.data() : their_ellswift.data(),
        initiating ? their_ellswift.data() : our_ellswift.data(),
        keys.secret_key, initiating ? 0 : 1, secp256k1_ellswift_xdh_hash_function_bip324, nullptr);
    if (!ret) {
        throw std::runtime_error("ECDH failed");
    }
    printf("EDCH secret:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", secret[i]);
    printf("\n");
    return tagged_hash(our_ellswift ,their_ellswift,secret);
}

Bytes ECDH_Initiator1(secp256k1_context* ctx, Keys &keys, Bytes &their_ellswift, Bytes &our_ellswift) {
    bool initiating{true};
    Bytes secret(32);
    int ret = secp256k1_ellswift_xdh(ctx,secret.data(), initiating ? our_ellswift.data() : their_ellswift.data(),
        initiating ? their_ellswift.data() : our_ellswift.data(),
        keys.secret_key, initiating ? 0 : 1, secp256k1_ellswift_xdh_hash_function_bip324, nullptr);
    if (!ret) {
        throw std::runtime_error("ECDH failed");
    }
    printf("EDCH secret:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", secret[i]);
    printf("\n");
    return secret;
}