//
// Created by filin on 1/5/26.
//

#include <vector>
#include <openssl/sha.h>

using Bytes = std::vector<uint8_t>;

Bytes SHA_256(const Bytes& data) {
    Bytes res(32);
    SHA256(data.data(), data.size(), res.data());
    return res;
}