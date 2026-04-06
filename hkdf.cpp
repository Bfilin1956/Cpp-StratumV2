//
// Created by filin on 12/30/25.
//
#include <vector>
#include <cstdint>
#include <cstdio>
#include <string_view>
using Bytes = std::vector<uint8_t>;

Bytes HMAC_SHA256(const Bytes& key, const Bytes& data);

void pr(Bytes input, std::string_view asd) {
    printf("%s:\t", asd.data());
    for (unsigned int i = 0; i < 32; i++)
        printf("%02x", input[i]);
    printf("\n");
}

std::pair<Bytes, Bytes> HKDF(Bytes ck, Bytes ikm) {

    pr(ck, "EKDF ck");
    Bytes temp_key = HMAC_SHA256(ck, ikm);        // temp_key = HMAC-HASH(ck, ikm)
    pr(temp_key, "EKDF temp_key");
    Bytes output1 = HMAC_SHA256(temp_key, {0x01});           // output1 = HMAC(temp_key, 0x01)
    pr(output1, "EKDF output1");
    Bytes out2_input = output1;


    out2_input.push_back(0x02);                 // output2 = HMAC(temp_key, output1 || 0x02)
    Bytes output2 = HMAC_SHA256(temp_key, out2_input);
    pr(output2, "EKDF output2");
    return {output1, output2};
}
