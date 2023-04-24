/*******************************************************************************
 *   TRON Ledger
 *   (c) 2018 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "helpers.h"
#include "base58.h"
#include "os_io_seproxyhal.h"
#include "crypto_helpers.h"

void getAddressFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *address) {
    return getAddressFromPublicKey(publicKey->W, address);
}

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t *address) {
    uint8_t hashAddress[32];
    cx_sha3_t sha3;

    cx_keccak_init(&sha3, 256);
    cx_hash((cx_hash_t *) &sha3, CX_LAST, publicKey + 1, 64, hashAddress, 32);

    memmove(address, hashAddress + 11, ADDRESS_SIZE);
    address[0] = ADD_PRE_FIX_BYTE_MAINNET;
}

void getBase58FromAddress(uint8_t *address, uint8_t *out, cx_sha256_t *sha2, bool truncate) {
    uint8_t sha256[32];
    uint8_t addchecksum[ADDRESS_SIZE + 4];

    cx_sha256_init(sha2);
    cx_hash((cx_hash_t *) sha2, CX_LAST, address, 21, sha256, 32);
    cx_sha256_init(sha2);
    cx_hash((cx_hash_t *) sha2, CX_LAST, sha256, 32, sha256, 32);

    memmove(addchecksum, address, ADDRESS_SIZE);
    memmove(addchecksum + ADDRESS_SIZE, sha256, 4);

    base58_encode(&addchecksum[0], 25, (char *) out, BASE58CHECK_ADDRESS_SIZE);
    out[BASE58CHECK_ADDRESS_SIZE] = '\0';
    if (truncate) {
        memmove((void *) out + 5, "...", 3);
        memmove((void *) out + 8,
                (const void *) (out + BASE58CHECK_ADDRESS_SIZE - 5),
                6);  // include \0 char
    }
}

void transactionHash(uint8_t *raw, uint16_t dataLength, uint8_t *out, cx_sha256_t *sha2) {
    cx_sha256_init(sha2);
    cx_hash((cx_hash_t *) sha2, CX_LAST, raw, dataLength, out, 32);
}

void signTransaction(transactionContext_t *transactionContext) {
    unsigned int info = 0;

    // Get Private key from BIP32 path
    io_seproxyhal_io_heartbeat();
    bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                        transactionContext->bip32_path.indices,
                                        transactionContext->bip32_path.length,
                                        CX_RND_RFC6979 | CX_LAST,
                                        CX_SHA256,
                                        transactionContext->hash,
                                        sizeof(transactionContext->hash),
                                        transactionContext->signature,
                                        transactionContext->signature + 32,
                                        &info);
    transactionContext->signature[64] = 0x00;
    if (info & CX_ECCINFO_PARITY_ODD) {
        transactionContext->signature[64] |= 0x01;
    }
    transactionContext->signatureLength = 65;

    return;
}
const unsigned char hex_digits[] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *) bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *) bin)) & 0xF];
        bin = (const void *) ((unsigned int) bin + 1);
    }
    *strbuf = 0;  // EOS
}

uint32_t set_result_get_publicKey(const publicKeyContext_t *pub_key_ctx) {
    uint32_t tx = 0;
    uint32_t addressLength = BASE58CHECK_ADDRESS_SIZE;
    G_io_apdu_buffer[tx++] = 65;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->publicKey.W, 65);
    tx += 65;
    G_io_apdu_buffer[tx++] = addressLength;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->address58, addressLength);
    tx += addressLength;
    if (pub_key_ctx->getChaincode) {
        memcpy(G_io_apdu_buffer + tx, pub_key_ctx->chainCode, 32);
        tx += 32;
    }
    return tx;
}
