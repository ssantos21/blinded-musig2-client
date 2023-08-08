#include <iostream>
#include <openssl/rand.h>

#include "utils/include_secp256k1_zkp_lib.h"
#include "utils/strencodings.h"

bool create_keypair(secp256k1_keypair &keypair) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char seckey[32];

    while (1) {
        if (RAND_bytes(seckey, sizeof(seckey)) != 1) {
            return false;
        }

        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }
    
    int return_val = secp256k1_keypair_create(ctx, &keypair, seckey);

    secp256k1_context_destroy(ctx);
    
    return return_val;
}

int main() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair keypair;
    if (!create_keypair(keypair)) {
        std::cout << "Failed to create keypair!" << std::endl;
        return 1;
    }

    unsigned char seckey[32];

    if (!secp256k1_keypair_sec(ctx, seckey, &keypair)) {
        std::cerr <<  "Failed to get the secret key from the key pair." << std::endl;
        return 1;
    }

    std::string seckey_hex = key_to_string(seckey, sizeof(seckey));

    std::cout <<  "seckey: " << seckey_hex << std::endl;

    // Here, you'd use the secp256k1-zkp functions...
    std::cout << "secp256k1-zkp integrated!" << std::endl;

    secp256k1_context_destroy(ctx);
    
    return 0;
}
