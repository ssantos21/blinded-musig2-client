#include "include_secp256k1_zkp_lib.h"
#include "../nlohmann/json.hpp"

using json = nlohmann::json;

bool create_keypair(secp256k1_keypair &keypair);

bool create_aggregate_key(
    const secp256k1_keypair &keypair,
    secp256k1_pubkey &server_pubkey,
    secp256k1_musig_keyagg_cache& cache,
    secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err);

bool save_signer_data(
    const secp256k1_keypair &keypair,
    const secp256k1_pubkey &server_pubkey,
    const secp256k1_musig_keyagg_cache& cache,
    const secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err);

bool load_signer_data(
    secp256k1_keypair &keypair,
    secp256k1_pubkey &server_pubkey,
    secp256k1_musig_keyagg_cache& cache,
    const secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err);