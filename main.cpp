#include <iostream>
#include <openssl/rand.h>
#include <sqlite3.h>

#include "cli/CLI11.hpp"
#include "fmt/core.h"
#include "nlohmann/json.hpp"
#include "utils/include_secp256k1_zkp_lib.h"
#include "utils/lib.h"
#include "utils/strencodings.h"

static int callback33(void* notUsed, int argc, char** argv, char** azColName) {
    for (int i = 0; i < argc; i++) {
        std::cout << azColName[i] << ": " << (argv[i] ? argv[i] : "NULL") << std::endl;
    }
    return 0;
}

int test_sqlite3() {
    std::cout << "sqlite3 integrated!" << std::endl;

    sqlite3* db;
    char* errorMessage = 0;

    // Connect to SQLite database (test.db)
    if (sqlite3_open("test.db", &db)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    // Create table if not exists
    const char* createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS data (
            keypair BLOB,
            aggregated_key BLOB,
            cache BLOB
        );
    )";

    if (sqlite3_exec(db, createTableSQL, callback33, 0, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }

    std::cout << "Done 1!" << std::endl;

    // Insert a sample record (using dummy data for demonstration purposes)
    const char* insertSQL = "INSERT INTO data (keypair, aggregated_key, cache) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertSQL, -1, &stmt, NULL) == SQLITE_OK) {
        // Binds are 1-indexed
        sqlite3_bind_blob(stmt, 1, "keypairData", 12, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, "aggregatedKeyData", 18, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, "cacheData", 9, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    std::cout << "Done 2!" << std::endl;

    // Query record by aggregated_key
    const char* querySQL = "SELECT * FROM data WHERE aggregated_key = ?;";
    if (sqlite3_prepare_v2(db, querySQL, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, "aggregatedKeyData", 18, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::cout << "Record found with keypair: " << sqlite3_column_text(stmt, 0) << std::endl;
        }
        sqlite3_finalize(stmt);
    }

    std::cout << "Done 3!" << std::endl;

    sqlite3_close(db);

    return 0;
}

void list_aggregated_public_keys() {

    std::vector<secp256k1_xonly_pubkey> aggregate_xonly_pubkeys;
    json res_err;

    if (!load_aggregated_public_keys(aggregate_xonly_pubkeys, res_err)) {
        std::cerr << res_err << std::endl;
        exit(1);
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    for (auto& aggregate_xonly_pubkey : aggregate_xonly_pubkeys) {
        unsigned char serialized_aggregate_xonly_pubkey[32];

        if (!secp256k1_xonly_pubkey_serialize(ctx, serialized_aggregate_xonly_pubkey, &aggregate_xonly_pubkey)) {
            std::cerr << "Failed to serialize the aggregated xonly public key." << std::endl;
            exit(1);
        }

        std::cout << key_to_string(serialized_aggregate_xonly_pubkey, sizeof(serialized_aggregate_xonly_pubkey)) << std::endl;


    }

    secp256k1_context_destroy(ctx);

    std::cout << "size: " << aggregate_xonly_pubkeys.size() << std::endl;
}

void create_aggregated_public_key() {
    secp256k1_keypair keypair;
    secp256k1_pubkey server_pubkey;
    secp256k1_xonly_pubkey aggregate_xonly_pubkey;
    secp256k1_musig_keyagg_cache cache;
    json res_err;

     if (!create_keypair(keypair)) {
        res_err = {
            {"error_code", 500},
            {"error_message", "Failed to generate a random number for the private key."}
        };
        std::cerr << res_err << std::endl;
        exit(1);
    }

    if (!create_aggregate_key(keypair, server_pubkey, cache, aggregate_xonly_pubkey, res_err)) {
        std::cerr << res_err << std::endl;
        exit(1);
    }

    if (!save_signer_data(keypair, server_pubkey, cache, aggregate_xonly_pubkey, res_err)) {
        std::cerr << res_err << std::endl;
        exit(1);
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    unsigned char serialized_aggregate_xonly_pubkey[32];
    int return_val = secp256k1_xonly_pubkey_serialize(ctx, serialized_aggregate_xonly_pubkey, &aggregate_xonly_pubkey);
    assert(return_val);

    json response = {{ "aggregate_xonly_pubkey", key_to_string(serialized_aggregate_xonly_pubkey, sizeof(serialized_aggregate_xonly_pubkey)) }};

    std::cout << response << std::endl;
}

void sign(std::string& aggregate_pubkey_hex, std::string& message) {

    std::cout << "aggregate_pubkey: " << aggregate_pubkey_hex << std::endl;
    std::cout << "message: " << message << std::endl;

    if (aggregate_pubkey_hex.substr(0, 2) == "0x") {
        aggregate_pubkey_hex = aggregate_pubkey_hex.substr(2);
    }

    if (message.substr(0, 2) == "0x") {
        message = message.substr(2);
    }

    std::vector<unsigned char> serialized_aggregate_xonly_pubkey = ParseHex(aggregate_pubkey_hex);

    secp256k1_xonly_pubkey aggregate_xonly_pubkey;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    if (!secp256k1_xonly_pubkey_parse(ctx, &aggregate_xonly_pubkey, serialized_aggregate_xonly_pubkey.data())) {
        std::cerr << "Failed to parse the aggregated xonly public key." << std::endl;
        exit(1);
    }

    json res_err;

    if (!sign(ctx, aggregate_xonly_pubkey, message, res_err)) {
        std::cerr << res_err << std::endl;
        exit(1);
    }

    secp256k1_context_destroy(ctx);
}

const std::string COMM_CREATE_AGGREGATED_PUBLIC_KEY = "create-aggregated-public-key";
const std::string COMM_LIST_AGGREGATED_PUBLIC_KEYS = "list-aggregated-public-keys";
const std::string COMM_SIGN = "sign";

int main(int argc, char **argv)
{
    /*
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

    test_sqlite3();
    */

    CLI::App app{"MuSig2 client"};
    app.set_version_flag("--version", std::string("0.0.1"));
    CLI::App *comm_create_aggregated_public_key = app.add_subcommand(COMM_CREATE_AGGREGATED_PUBLIC_KEY, "Request server's public key and use it to create aggregated public key.");
    CLI::App *comm_list_aggregated_public_keys = app.add_subcommand(COMM_LIST_AGGREGATED_PUBLIC_KEYS, "List stored aggregated public keys.");
    CLI::App *comm_sign = app.add_subcommand(COMM_SIGN, "Sign a message.");

    std::string aggregate_pubkey;
    std::string message;

    comm_sign->add_option("-a,--aggregate-pubkey", aggregate_pubkey, "Aggregate pubkey")->required(true);
    comm_sign->add_option("-m,--message", message, "Message")->required(true);

    app.require_subcommand();
    CLI11_PARSE(app, argc, argv);

    if (app.get_subcommands().size() > 1) {
        std::cerr << "Only one command is allowed" << std::endl;
        return 1;
    }

    CLI::App *subcom = app.get_subcommands().at(0);

    if (subcom == comm_create_aggregated_public_key) {
        create_aggregated_public_key();
    } else if (subcom == comm_list_aggregated_public_keys) {
        list_aggregated_public_keys();
    } else if (subcom == comm_sign) {
        sign(aggregate_pubkey, message);
    } else {
        std::cerr << "Unknown command" << std::endl;
        return 1;
    }
    
    return 0;
}
