#include <cassert>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <vector>
#include <span>
#include <stdexcept>
#include <string>
#include <boost/asio.hpp>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_schnorrsig.h>

#include "examples_util.h"
secp256k1_context* ctx;

#define TEST printf("\n\nGood\n\n");

using Bytes = std::vector<uint8_t>;
using BytesView = std::span<const uint8_t>;
Bytes key = Bytes(
       {'N','o','i','s','e','_','N','X','_',
        'S','e','c','p','2','5','6','k','1',
        '+','E','l','l','S','w','i','f','t',
        '_','C','h','a','C','h','a','P','o','l','y',
        '_','S','H','A','2','5','6'}
   );





struct CipherState {
    unsigned char key[32]{};
    uint64_t nonce = 0;

    bool has_key = false;

    void InitializeKey(const unsigned char k[32]) {
        memcpy(key, k, 32);
        nonce = 0;
        has_key = true;
    }

    Bytes EncryptWithAd(Bytes ad, Bytes plaintext);
    Bytes DecryptWithAd(Bytes ad, Bytes ciphertext);
};


struct Keys {
    unsigned char secret_key[32]{};
    unsigned char public_key[33]{};
    unsigned char x_only_public_key[32]{};
    secp256k1_pubkey pubKey;
    unsigned char ellswift_pubkey_e[64]{};
    unsigned char ellswift_pubkey_re[64]{};
    Bytes ck;     // chaining key
    Bytes h;      // handshake hash
    CipherState cs;
    unsigned char ecdh_x[32]{};
    unsigned char temp_k[32]{};
    bool has_rs = false;
    unsigned char ellswift_pubkey_rs[64]{};
};
Keys keys1;
Bytes SHA_256(const Bytes& data) ;
Bytes HMAC_SHA256(const Bytes& key, const Bytes& data);
std::pair<Bytes, Bytes> HKDF(Bytes ck, Bytes ikm);
Bytes ECDH_Initiator(secp256k1_context* ctx, Keys &keys);
Bytes ECDH_Initiator(secp256k1_context* ctx, Keys &keys, Bytes &their_ellswift, Bytes &our_ellswift);
Bytes ECDH_Initiator1(secp256k1_context* ctx, Keys &keys, Bytes &their_ellswift, Bytes &our_ellswift);
#include <boost/multiprecision/cpp_int.hpp>
using boost::multiprecision::cpp_int;
cpp_int to_decimal(const uint8_t* data, size_t len) {
    cpp_int x = 0;
    for (size_t i = 0; i < len; ++i) {
        x <<= 8;          // умножение на 256
        x += data[i];     // big-endian
    }
    return x;
}

void hexStringToBytes(const std::string &hex, unsigned char* out, size_t out_size) {
    assert(hex.size() == out_size * 2); // проверка размера
    for (size_t i = 0; i < out_size; ++i) {
        unsigned int byte;
        sscanf(hex.c_str() + 2*i, "%02x", &byte);
        out[i] = static_cast<unsigned char>(byte);
    }
}

void generate_key() {
    do {
        fill_random(keys1.secret_key, 32);
    } while (!secp256k1_ec_seckey_verify(ctx, keys1.secret_key));
    int ret = secp256k1_ec_pubkey_create(ctx, &keys1.pubKey, keys1.secret_key);

    //std::string test_hex = "e558ec56fe54aa23ff599f879c9c9bd5c9a8f79801e4d7d9fa4912205eb86477";
    //hexStringToBytes(test_hex, keys1.secret_key, 32);

    printf("SecretKey:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.secret_key[i]);
    printf("\n");

    size_t lenn = 33;
    secp256k1_ec_pubkey_serialize(ctx,keys1.public_key, &lenn, &keys1.pubKey,SECP256K1_EC_COMPRESSED);
    memcpy(keys1.x_only_public_key, keys1.public_key+1, 32);
    printf("PublicKey:\t");
    for (unsigned int i = 0; i < 33; i++)
        printf("%02x", keys1.public_key[i]);
    printf("\n");

    printf("x_only_public_key:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.x_only_public_key[i]);
    printf("\n");

    assert(ret);
    unsigned char auxrand[32];
    if (!fill_random(auxrand, sizeof(auxrand))) {
        printf("Failed to generate randomness\n");
        return ;
    }

    int return_val = secp256k1_ellswift_create(ctx, keys1.ellswift_pubkey_e, keys1.secret_key, auxrand);
    assert(return_val);

    //std::string test_hex1 = "66e4c81dc599827ab27040a8658ec9fb71acb79d61375c80fc2a460251f49ac738bf1f0685746c4a6a2a1e6a57d5defb29d9ef1cfbea56520af4517c573fcf00";
    //hexStringToBytes(test_hex1, keys1.ellswift_pubkey_e, 64);

    printf("EllsKeyX:\t");
    for (unsigned int i = 0; i < 64; i++)
        printf("%02x", keys1.ellswift_pubkey_e[i]);
    printf("\n");
}

Bytes tagged_hash(Bytes &a, Bytes &b, Bytes &c) {
    std::string tag{"bip324_ellswift_xonly_ecdh"};
    Bytes tagg(tag.begin(), tag.end());
    Bytes res = SHA_256(tagg);

    Bytes buf;
    buf.insert(buf.end(), res.begin(), res.end());
    buf.insert(buf.end(), res.begin(), res.end());
    buf.insert(buf.end(), a.begin(), a.end());
    buf.insert(buf.end(), b.begin(), b.end());
    buf.insert(buf.end(), c.begin(), c.end());

    return SHA_256(buf);
}

void MixHash(Keys& st, const Bytes& data1) {
    std::cout << "MixHash STARTED\n";
    Bytes tmp = st.h;
    tmp.insert(tmp.end(), data1.begin(), data1.end());
    st.h = SHA_256(tmp);
}

void MixKey(Keys& st, const Bytes& ikm) {
    auto [new_ck, temp_k] = HKDF(st.ck, ikm);

    printf("temp_k:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", temp_k[i]);
    printf("\n");

    st.ck = new_ck;
    st.cs.InitializeKey(temp_k.data());
}

Bytes CipherState::EncryptWithAd(Bytes ad, Bytes plaintext) {
    assert(has_key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    unsigned char nonce96[12] = {};
    uint64_t le_nonce = nonce; 
    memcpy(nonce96 + 4, &le_nonce, 8);

    Bytes out;
    out.resize(plaintext.size() + 16);
    int out_len = 0;
    int len = 0;


    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce96);

    if (!ad.empty()) {
        EVP_EncryptUpdate(ctx, nullptr, &len, ad.data(), ad.size());
    }

    EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), plaintext.size());
    out_len = len;

    EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
    out_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + out_len);
    out_len += 16;

    out.resize(out_len);
    EVP_CIPHER_CTX_free(ctx);

    nonce++;
    return out;
}

Bytes CipherState::DecryptWithAd(Bytes ad, Bytes ciphertext) {
    if (ciphertext.size() < 16) throw std::runtime_error("Ciphertext too short");

    size_t ct_len = ciphertext.size() - 16;
    const unsigned char* tag = ciphertext.data() + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    unsigned char nonce96[12] = {};
    uint64_t le_nonce = nonce;
    memcpy(nonce96 + 4, &le_nonce, 8);

    Bytes out;
    out.resize(ct_len);
    int len = 0;
    int out_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce96);

    if (!ad.empty()) {
        EVP_DecryptUpdate(ctx, nullptr, &len, ad.data(), ad.size());
    }

    EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(), ct_len);
    out_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);

    int ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
    out_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (ok != 1) {
        throw std::runtime_error("AEAD tag mismatch");
    }

    out.resize(out_len);
    nonce++;
    return out;
}


Bytes PROTOCOL_NAME_HASH = {
46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14,
169, 234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16};

Bytes EncryptAndHash(Bytes plain) {
    if (!keys1.cs.has_key) {
        MixHash(keys1, {});
        return plain;
    }
    Bytes out123;
    if (keys1.cs.has_key) {
        out123 =  keys1.cs.EncryptWithAd(keys1.h, plain);
    }
    MixHash(keys1, plain);
    return out123;
}

Bytes DecryptAndHash(Bytes plain) {
    if (!keys1.cs.has_key) {
        MixHash(keys1, {});
        return plain;
    }
    Bytes out123;
    if (keys1.cs.has_key) {
       out123 =  keys1.cs.DecryptWithAd(keys1.h, plain);
    }
    MixHash(keys1, plain);
    return out123;
}

int main() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    generate_key();

    keys1.h = PROTOCOL_NAME_HASH ;


    printf("keys1.h:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.h[i]);
    printf("\n");

    keys1.ck = keys1.h;

    printf("keys1.ck:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.ck[i]);
    printf("\n");

    keys1.h = SHA_256(keys1.h);

    printf("keys1.h:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.h[i]);
    printf("\n");

    Bytes out_buffer(keys1.ellswift_pubkey_e, keys1.ellswift_pubkey_e+64);

    printf("out_buffer:\t");
    for (unsigned int i = 0; i < 64; i++)
        printf("%02x", out_buffer[i]);
    printf("\n");

    MixHash(keys1, out_buffer);



    printf("MixHash:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.h[i]);
    printf("\n");

    EncryptAndHash(out_buffer);

    printf("MixHash:\t");
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", keys1.h[i]);
    printf("\n");
    try {
        boost::asio::io_context io_context;
        //107.170.42.64 - braiin 3336
        //75.119.150.111 - stratum v2 43333
        std::string ip = "107.170.42.64";
        unsigned short port = 3336;
        boost::asio::ip::tcp::socket socket(io_context);
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(ip), port);
        socket.connect(endpoint);
        boost::asio::write(socket, boost::asio::buffer(out_buffer.data(), out_buffer.size()));

    // отправил 64 байта хуйни - Фаза 1 инициатора ---------------------------------------


        Bytes in_buffer(234,0);
        //std::string test_hex = "7e67322daa731bd762c0b47be332a18a7c62d62e5999de4a41a5572b981c162a4bf758fc2b044fe5f67555ab7bacc6f9e81dfd1162966b5bfff773bf311cf4e67e461a27687d3dd8cb86e3bc61b66568598602a04de0b6f604689ab3cf7d9c30aaca1b92ab9d2cff617c3055f964d1e7f0b0abf3f4b1c6c2975cc63072c175a03776e0e6888cfe5d6477aeee580c7f1301f281ad002791ea202fbe2b0691dd03c0307f7a98a8a135c7509da99d30f958699e55c6d4e8a51834cb15ce7eb79c2abc7aad9a4e9c1cfdad3a01770f0aaacd9622b61f992a769d3927e850684a841cc4117e0e27cb1e5f1ef3";
        //hexStringToBytes(test_hex, in_buffer.data(), 234);
        boost::asio::read(socket, boost::asio::buffer(in_buffer.data(), in_buffer.size()));
        printf("in_buffer:\t");
        for (unsigned int i = 0; i < 234; i++)
            printf("%02x", in_buffer[i]);
        printf("\n");
        memcpy(keys1.ellswift_pubkey_re, in_buffer.data(), 64); //64 байта

        printf("keys1.ellswift_pubkey_re:\t");
        for (unsigned int i = 0; i < 64; i++)
            printf("%02x", keys1.ellswift_pubkey_re[i]);
        printf("\n");

        Bytes x1_ellswift_pubkey2(keys1.ellswift_pubkey_re,keys1.ellswift_pubkey_re+64);

        printf("x1_ellswift_pubkey2:\t");
        for (unsigned int i = 0; i < 64; i++)
            printf("%02x", keys1.ellswift_pubkey_re[i]);
        printf("\n");

        MixHash(keys1, x1_ellswift_pubkey2);

        printf("MixHash:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", keys1.h[i]);
        printf("\n");

        Bytes x90(keys1.ellswift_pubkey_e, keys1.ellswift_pubkey_e+64);

        MixKey(keys1, ECDH_Initiator1(ctx, keys1, x1_ellswift_pubkey2,x90));

        Bytes temp2(80);

        memcpy(temp2.data(), in_buffer.data()+64, 80); //64+64

        printf("temp2:\t");
        for (unsigned int i = 0; i < 80; i++)
            printf("%02x", temp2[i]);
        printf("\n");
        Bytes temp123 = DecryptAndHash(temp2);

        memcpy(keys1.ellswift_pubkey_rs, temp123.data(), 64);
        printf("temp123:\t");
        for (unsigned int i = 0; i < 64; i++)
            printf("%02x", temp123[i]);
        printf("\n");
        std::cout << "temp123:\t " << temp123.size() << std::endl;
        printf("MixHash:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", keys1.h[i]);
        printf("\n");
        TEST



        MixKey(keys1, ECDH_Initiator1(ctx, keys1, temp123,x90));

        Bytes temp321(90);
        memcpy(temp321.data(), in_buffer.data()+64+80, 90);
        printf("temp321:\t");
        for (unsigned int i = 0; i < 90; i++)
            printf("%02x", temp321[i]);
        printf("\n");
        Bytes temp1232 = DecryptAndHash( temp321);
        printf("temp1232:\t");
        for (unsigned int i = 0; i < 74; i++)
            printf("%02x", temp1232[i]);
        printf("\n");
        Bytes empty_vec(32,0);
        TEST
        auto[первый_ебень, второй] = HKDF(keys1.ck, {});
        CipherState c1;
        CipherState c2;

        c1.InitializeKey(первый_ебень.data());
        c2.InitializeKey(второй.data());
        TEST
        printf("Урод номер 1:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", первый_ебень[i]);
        printf("\n");

        printf("Урод номер 2:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", второй[i]);
        printf("\n");

        Bytes xzxz(42);
        memcpy(xzxz.data(), temp1232.data(), 10);
        secp256k1_pubkey pubkey;

        printf("xzxz:\t");
        for (unsigned int i = 0; i < 42; i++)
            printf("%02x", xzxz[i]);
        printf("\n");

        int ok = secp256k1_ellswift_decode(
            ctx,
            &pubkey,
            keys1.ellswift_pubkey_rs  // 64 bytes
        );

        printf("keys1.ellswift_pubkey_rs :\t");
        for (unsigned int i = 0; i < 64; i++)
            printf("%02x", keys1.ellswift_pubkey_rs [i]);
        printf("\n");
        secp256k1_xonly_pubkey xonly;
        int parity = 0;

        secp256k1_xonly_pubkey_from_pubkey(           ctx,
            &xonly,
            &parity,
            &pubkey
        );
        unsigned char x32[32];
        secp256k1_xonly_pubkey_serialize(
            ctx,
            x32,
            &xonly
        );
        memcpy(keys1.x_only_public_key, x32, 32);

        printf("x32static_r:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", x32[i]);
        printf("\n");

        memcpy(xzxz.data()+10, x32, 32);
        printf("xzxz:\t");
        for (unsigned int i = 0; i < 42; i++)
            printf("%02x", xzxz[i]);
        printf("\n");

        Bytes m = SHA_256(xzxz);
        printf("m:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", m[i]);
        printf("\n");

        Bytes dsds1(38);
        std::string test_hex32 = "010029954c97456b599c836f70f508d619d328527bb87229d7d7d2e67e6dcd18ebcfb6cc89ab";
        hexStringToBytes(test_hex32, dsds1.data(), 38);
        printf("dsds1:\t");
        for (unsigned int i = 0; i < 38; i++)
            printf("%02x", dsds1[i]);
        printf("\n");
        Bytes dsds2(32);
        memcpy(dsds2.data(), dsds1.data()+2, 32);
        printf("dsds:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", dsds2[i]);
        printf("\n");

        secp256k1_xonly_pubkey ca_pub2;
        secp256k1_xonly_pubkey_parse(ctx, &ca_pub2, dsds2.data());

        unsigned char x322[32];
        secp256k1_xonly_pubkey_serialize(
            ctx,
            x322,
            &ca_pub2
        );

        printf("x322:\t");
        for (unsigned int i = 0; i < 32; i++)
            printf("%02x", x322[i]);
        printf("\n");

        Bytes sig(64);
        memcpy(sig.data(), temp1232.data()+10, 64);
        int ok1 = secp256k1_schnorrsig_verify(
            ctx,
            sig.data(),
            m.data(),
            32,
            &ca_pub2
        );

        if (!ok1) {
            printf("secp256k1_schnorrsig_verify:\t Пизда полная\n");
        } else {
            printf("secp256k1_schnorrsig_verify:\t Сертификат прошел проверку\n");
        }


    } catch (std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << "\n";
    }
    secp256k1_context_destroy(ctx);
}
