#include "../crypto/sha256sum.h"
#include "../nlohmann/json.hpp"
#include "include_secp256k1_zkp_lib.h"
#include "lib.h"
#include "strencodings.h"

#include <assert.h>
#include <iostream>
#include <cpr/cpr.h>
#include <openssl/rand.h>
#include <sqlite3.h>

using json = nlohmann::json;

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

bool extract_keys_from_keypair(
    const secp256k1_context *ctx,
    const secp256k1_keypair &keypair,
    unsigned char seckey[32], 
    secp256k1_pubkey& pubkey, 
    unsigned char compressed_pubkey[33], 
    int compressed_pubkey_size,
    std::string& error_message) {

    if (!secp256k1_keypair_sec(ctx, seckey, &keypair)) {
        error_message = "Failed to get the secret key from the key pair.";
        return false;
    }

    if (!secp256k1_keypair_pub(ctx, &pubkey, &keypair)) {
        error_message = "Failed to get the public key from the key pair.";
        return false;
    }

    // Serialize pubkey2 in a compressed form (33 bytes)
    size_t len = compressed_pubkey_size;
    int return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    // Should be the same size as the size of the output, because we passed a 33 byte array.
    if (len != compressed_pubkey_size) {
        error_message = "The serialized public key must be a 33-byte array.";
        return false;
    }

    return true;
}

bool create_aggregate_key(
    const secp256k1_keypair &keypair,
    secp256k1_pubkey &server_pubkey,
    secp256k1_musig_keyagg_cache& cache,
    secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err) {

    unsigned char client_seckey[32];
    secp256k1_pubkey client_pubkey;
    unsigned char client_compressed_pubkey[33];

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    std::string error_message;
    bool return_val = extract_keys_from_keypair(
        ctx, keypair, client_seckey, client_pubkey, client_compressed_pubkey, sizeof(client_compressed_pubkey), error_message
    );

    if (!return_val) {
        res_err = {
            {"error_code", 1},
            {"error_message", error_message}
        };

        secp256k1_context_destroy(ctx);
        return false;
    }

    auto pubkey_str = key_to_string(client_compressed_pubkey, sizeof(client_compressed_pubkey));

    json params = {{ "client_pubkey", pubkey_str }};

    cpr::Response r = cpr::Post(cpr::Url{"http://0.0.0.0:18080/get_public_key"}, cpr::Body{params.dump()});

    if (r.status_code == 200 && r.header["content-type"] == "application/json") {

        auto res_json = json::parse(r.text);

        assert(res_json["server_pubkey"].is_string());
        std::string server_pubkey_str = res_json["server_pubkey"];

        // Check if the string starts with 0x and remove it if necessary
        if (server_pubkey_str.substr(0, 2) == "0x") {
            server_pubkey_str = server_pubkey_str.substr(2);
        }

        std::vector<unsigned char> server_pubkey_serialized = ParseHex(server_pubkey_str);

        // Deserialize the public key
        if (!secp256k1_ec_pubkey_parse(ctx, &server_pubkey, server_pubkey_serialized.data(), server_pubkey_serialized.size())) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to parse server public key."}
            };
            secp256k1_context_destroy(ctx);
            return false;
        }

        const secp256k1_pubkey *pubkeys_ptr[2];

        pubkeys_ptr[0] = &client_pubkey;
        pubkeys_ptr[1] = &server_pubkey;

        if (!secp256k1_musig_pubkey_agg(ctx, NULL, &aggregate_xonly_pubkey, &cache, pubkeys_ptr, 2)) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to compute an aggregate public key and initialize a keyagg_cache."}
            };
            secp256k1_context_destroy(ctx);
            return false;
        }

        secp256k1_context_destroy(ctx);
        return true;
    } else {
        res_err = {
            {"error_code", r.status_code},
            {"error_message", r.text}
        };
        secp256k1_context_destroy(ctx);
        return false;
    }
}

bool save_signer_data(
    const secp256k1_keypair &keypair,
    const secp256k1_pubkey &server_pubkey,
    const secp256k1_musig_keyagg_cache& cache,
    const secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err) 
{
    sqlite3* db;
    char* errorMessage = 0;

    // Connect to SQLite database (test.db)
    if (sqlite3_open("wallet.db", &db)) {
        std::string errmsg(sqlite3_errmsg(db));
        res_err = {
            {"error_code", 1},
            {"error_message", "Can't open database: " + errmsg}
        };
        return false;
    }

    // Create table if not exists
    const char* createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS signer_data (
            keypair BLOB,
            server_pubkey BLOB,
            aggregated_key BLOB,
            cache BLOB
        );
    )";

    if (sqlite3_exec(db, createTableSQL, 0, 0, &errorMessage) != SQLITE_OK) {
        std::string errmsg(errorMessage);
        res_err = {
            {"error_code", 1},
            {"error_message", "Can't open database: " + errmsg}
        };
        sqlite3_free(errorMessage);
        return false;
    }

    unsigned char serialized_server_pubkey[33];
    unsigned char serialized_aggregate_xonly_pubkey[32];

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    size_t len = sizeof(serialized_server_pubkey);
    int return_val = secp256k1_ec_pubkey_serialize(ctx, serialized_server_pubkey, &len, &server_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
    assert(len == sizeof(serialized_server_pubkey));

    return_val = secp256k1_xonly_pubkey_serialize(ctx, serialized_aggregate_xonly_pubkey, &aggregate_xonly_pubkey);
    assert(return_val);

    sqlite3_stmt* stmt;
    const char* insertSQL = "INSERT INTO signer_data(keypair, server_pubkey, aggregated_key, cache) VALUES(?, ?, ?, ?);";

    std::cout <<  "keypair: " << key_to_string(keypair.data, sizeof(keypair.data)) << std::endl;
    std::cout <<  "server_pubkey: " << key_to_string(serialized_server_pubkey, sizeof(serialized_server_pubkey)) << std::endl;
    std::cout <<  "aggregate_xonly_pubkey: " << key_to_string(serialized_aggregate_xonly_pubkey, sizeof(serialized_aggregate_xonly_pubkey)) << std::endl;
    std::cout <<  "cache: " << key_to_string(cache.data, sizeof(cache.data)) << std::endl;

    if (sqlite3_prepare_v2(db, insertSQL, -1, &stmt, NULL) == SQLITE_OK) {

        // Bind the byte array to the placeholder
        sqlite3_bind_blob(stmt, 1, keypair.data, sizeof(keypair.data), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, serialized_server_pubkey, sizeof(serialized_server_pubkey), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, serialized_aggregate_xonly_pubkey, sizeof(serialized_aggregate_xonly_pubkey), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 4, cache.data, sizeof(cache.data), SQLITE_STATIC);

        // Execute the statement
        sqlite3_step(stmt);

        // Finalize the statement
        sqlite3_finalize(stmt);
    }

    secp256k1_context_destroy(ctx);

    sqlite3_close(db);

    return true;
}

bool load_signer_data(
    secp256k1_keypair &keypair,
    secp256k1_pubkey &server_pubkey,
    secp256k1_musig_keyagg_cache& cache,
    const secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err) 
{
    sqlite3* db;
    char* errorMessage = 0;

    // Connect to SQLite database (test.db)
    if (sqlite3_open("wallet.db", &db)) {
        std::string errmsg(sqlite3_errmsg(db));
        res_err = {
            {"error_code", 1},
            {"error_message", "Can't open database: " + errmsg}
        };
        return false;
    }

    unsigned char serialized_aggregate_xonly_pubkey[32];

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    int return_val = secp256k1_xonly_pubkey_serialize(ctx, serialized_aggregate_xonly_pubkey, &aggregate_xonly_pubkey);
    assert(return_val);

    sqlite3_stmt* stmt;
    const char* querySQL = "SELECT keypair, server_pubkey, cache FROM signer_data WHERE aggregated_key = ?;";

    if (sqlite3_prepare_v2(db, querySQL, -1, &stmt, NULL) != SQLITE_OK) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to execute statement"}
        };
        
        secp256k1_context_destroy(ctx);
        return false;
    }
    
    sqlite3_bind_blob(stmt, 1, serialized_aggregate_xonly_pubkey, sizeof(serialized_aggregate_xonly_pubkey), SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* keypair_blob = sqlite3_column_blob(stmt, 0);
        const void* server_pubkey_blob = sqlite3_column_blob(stmt, 1);
        const void* cache_blob = sqlite3_column_blob(stmt, 2);

        size_t keypair_blob_size = sqlite3_column_bytes(stmt, 0);
        size_t server_pubkey_blob_size = sqlite3_column_bytes(stmt, 1);
        size_t cache_blob_size = sqlite3_column_bytes(stmt, 2);

        std::cout << "keypair_blob_size: " << keypair_blob_size << std::endl;
        std::cout << "server_pubkey_blob_size: " << server_pubkey_blob_size << std::endl;
        std::cout << "cache_blob_size: " << cache_blob_size << std::endl;

        unsigned char serialized_server_pubkey[33];

        assert(keypair_blob_size == sizeof(keypair.data));
        assert(server_pubkey_blob_size == sizeof(serialized_server_pubkey));
        assert(cache_blob_size == sizeof(cache.data));

        memcpy(keypair.data, keypair_blob, sizeof(keypair.data));
        memcpy(serialized_server_pubkey, server_pubkey_blob, sizeof(serialized_server_pubkey));
        memcpy(cache.data, cache_blob, sizeof(cache.data));

        memset(server_pubkey.data, 0, sizeof(server_pubkey.data));

        std::cout <<  "keypair: " << key_to_string(keypair.data, sizeof(keypair.data)) << std::endl;
        std::cout <<  "server_pubkey: " << key_to_string(serialized_server_pubkey, sizeof(serialized_server_pubkey)) << std::endl;
        std::cout <<  "cache: " << key_to_string(cache.data, sizeof(cache.data)) << std::endl;

        return_val = secp256k1_ec_pubkey_parse(ctx, &server_pubkey, serialized_server_pubkey, sizeof(serialized_server_pubkey));

        // Finalize the statement
        sqlite3_finalize(stmt);

        sqlite3_close(db);

        secp256k1_context_destroy(ctx);
        return true;
    } else {
        res_err = {
            {"error_code", 1},
            {"error_message", "No data found"}
        };
        secp256k1_context_destroy(ctx);
        return false;
    }
    
}

bool load_aggregated_public_keys(std::vector<secp256k1_xonly_pubkey>& aggregate_xonly_pubkeys, json& res_err) {
    sqlite3* db;
    char* errorMessage = 0;

    // Connect to SQLite database (test.db)
    if (sqlite3_open("wallet.db", &db)) {
        std::string errmsg(sqlite3_errmsg(db));
        res_err = {
            {"error_code", 1},
            {"error_message", "Can't open database: " + errmsg}
        };
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    sqlite3_stmt* stmt;
    const char* querySQL = "SELECT aggregated_key FROM signer_data;";

    if (sqlite3_prepare_v2(db, querySQL, -1, &stmt, NULL) != SQLITE_OK) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to execute statement"}
        };
        
        secp256k1_context_destroy(ctx);
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* aggregate_xonly_pubkey_blob = sqlite3_column_blob(stmt, 0);
        size_t aggregate_xonly_pubkey_blob_size = sqlite3_column_bytes(stmt, 0);

        // the size of serialized xonly pubkey is 32 bytes
        assert(aggregate_xonly_pubkey_blob_size == 32);

        secp256k1_xonly_pubkey aggregate_xonly_pubkey;

        int return_val = secp256k1_xonly_pubkey_parse(ctx, &aggregate_xonly_pubkey, (unsigned char*)aggregate_xonly_pubkey_blob);

        if (return_val) {
            aggregate_xonly_pubkeys.push_back(aggregate_xonly_pubkey);
        }
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    sqlite3_close(db);

    secp256k1_context_destroy(ctx);
    return true;
}

bool sign(
    secp256k1_context* ctx,
    const secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    const std::string& message,
    json& res_err) 
{
    secp256k1_keypair keypair;
    secp256k1_pubkey server_pubkey;
    secp256k1_musig_keyagg_cache cache;

    if (!load_signer_data(keypair, server_pubkey, cache, aggregate_xonly_pubkey, res_err)) {
        return false;
    }

    std::string message_hash;
    unsigned char msg32[32];

    if (!get_sha256("execute_complete_scheme test", message_hash)) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to hash the message!"}
        };
        return false;
    } 

    if (message_hash.size() != 64) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Invalid message hash length. Must be 32 bytes!"}
        };
        return false;
    }

    if (!hex_to_bytes(message_hash, msg32)) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Invalid message hash!"}
        };
        return false;
    }

    unsigned char client_seckey[32];
    secp256k1_pubkey client_pubkey;

    if (!secp256k1_keypair_sec(ctx, client_seckey, &keypair)) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to get the secret key from the key pair."}
        };
        return false;
    }

    if (!secp256k1_keypair_pub(ctx, &client_pubkey, &keypair)) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to get the public key from the key pair."}
        };
        return false;
    }

    secp256k1_musig_secnonce client_secnonce;
    secp256k1_musig_pubnonce client_pubnonce;

    unsigned char session_id[32];

    if (RAND_bytes(session_id, sizeof(session_id)) != 1) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to generate a random number for the session id!"}
        };
        return false;
    }

    if (!secp256k1_musig_nonce_gen(ctx, &client_secnonce, &client_pubnonce, session_id, client_seckey, &client_pubkey, msg32, NULL, NULL)) {
        res_err = {
            {"error_code", 1},
            {"error_message", "Failed to initialize session and create the nonces!"}
        };
        return false;
    }

    secp256k1_musig_session session;
    secp256k1_musig_partial_sig client_partial_sig;

    unsigned char serialized_server_pubkey[33];

    size_t len = sizeof(serialized_server_pubkey);
    int return_val = secp256k1_ec_pubkey_serialize(ctx, serialized_server_pubkey, &len, &server_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
    assert(len == sizeof(serialized_server_pubkey));

    auto server_public_pubkey_hex = key_to_string(serialized_server_pubkey, sizeof(serialized_server_pubkey));
    auto msg32_hex = key_to_string(msg32, sizeof(msg32));

    json params = {{ "server_public_pubkey", server_public_pubkey_hex }, {"message_hash", msg32_hex}};

    cpr::Response r = cpr::Post(cpr::Url{"http://0.0.0.0:18080/get_public_nonce"}, cpr::Body{params.dump()});

    if (r.status_code == 200 && r.header["content-type"] == "application/json") {

        auto res_json = json::parse(r.text);

        assert(res_json["server_pubnonce"].is_string());
        std::string server_pubnonce_str = res_json["server_pubnonce"];

        // Check if the string starts with 0x and remove it if necessary
        if (server_pubnonce_str.substr(0, 2) == "0x") {
            server_pubnonce_str = server_pubnonce_str.substr(2);
        }

        std::vector<unsigned char> server_pubnonce_serialized = ParseHex(server_pubnonce_str);

        secp256k1_musig_pubnonce server_pubnonce;
        secp256k1_musig_pubnonce_parse(ctx, &server_pubnonce, server_pubnonce_serialized.data());

        auto server_pubnonce_data_hex = key_to_string(server_pubnonce.data, sizeof(server_pubnonce.data));
        std::cout << "server_pubnonce_data_hex: " << server_pubnonce_data_hex << std::endl;
        
        
    } else {
        res_err = {
            {"error_code", r.status_code},
            {"error_message", r.text}
        };
        secp256k1_context_destroy(ctx);
        return false;
    }

    return true;

}