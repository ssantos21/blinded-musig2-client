#include <iostream>
#include <openssl/rand.h>
#include <sqlite3.h>

#include "utils/include_secp256k1_zkp_lib.h"
#include "utils/strencodings.h"

static int callback33(void* notUsed, int argc, char** argv, char** azColName) {
    for (int i = 0; i < argc; i++) {
        std::cout << azColName[i] << ": " << (argv[i] ? argv[i] : "NULL") << std::endl;
    }
    return 0;
}

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

    test_sqlite3();
    
    return 0;
}
