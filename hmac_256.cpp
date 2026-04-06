//
// Created by filin on 12/30/25.
//

#include <vector>
#include <openssl/hmac.h>

using Bytes = std::vector<uint8_t>;



Bytes HMAC_SHA256(const Bytes& key, const Bytes& data = {}) {
    Bytes result_hmac(32, 0);
    unsigned int len = 0;
    HMAC(
        EVP_sha256(),
        key.data(), static_cast<int>(key.size()),
        data.data(), static_cast<int>(data.size()),
        result_hmac.data(),
        &len
    );
    return result_hmac;
}


