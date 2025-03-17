#include "crypto.h"

int chacha20_decrypt(const uint8_t key[CHACHA_KEY_SIZE],
                     const uint8_t* in,
                     size_t len,
                     const uint8_t tag[TAG_LENGTH],
                     const uint8_t* ad,
                     size_t ad_len,
                     const uint8_t nonce[NONCE_SIZE],
                     uint8_t* out) {
    int status = wc_ChaCha20Poly1305_Decrypt(key, nonce, ad, ad_len, in, len, tag, out);
    if (status == 0) {
        return SUCCESS;
    }
    if (status == BAD_FUNC_ARG) {
        return ERROR;
    }

    if (status == MAC_CMP_FAILED_E) {
        return TAG_ERROR;
    }

    return ERROR;  // generic error
}

int decrypt_frame_ad_buf(const uint8_t key[CHACHA_KEY_SIZE],
                         const uint8_t additional_data[sizeof(uint32_t) + sizeof(uint64_t) + NONCE_SIZE],
                         const uint8_t encrypted_frame[CRYPTO_FRAME_SIZE],
                         const uint8_t tag[TAG_LENGTH],
                         uint8_t* out) {
    size_t ad_size = sizeof(uint32_t) + sizeof(uint64_t) + NONCE_SIZE;
    return chacha20_decrypt(key,
                            encrypted_frame,
                            CRYPTO_FRAME_SIZE,
                            tag,
                            additional_data,
                            ad_size,
                            additional_data + ad_size - NONCE_SIZE,
                            out);
    
}

int decrypt_frame(const uint8_t key[CHACHA_KEY_SIZE],
                  uint32_t channel_no,
                  uint64_t frame_no,
                  const uint8_t nonce[NONCE_SIZE],
                  const uint8_t encrypted_frame[CRYPTO_FRAME_SIZE],
                  const uint8_t tag[TAG_LENGTH],
                  uint8_t* out) {
    int offset = 0;

    // allocate buffer for additional data
    size_t ad_size = sizeof(channel_no) + sizeof(frame_no) + NONCE_SIZE;
    uint8_t additional_data[ad_size];

    memcpy((void*)(additional_data + offset), (void*)(&channel_no), sizeof(channel_no));  // copy the channel number to the AD
    offset += sizeof(channel_no);

    memcpy((void*)(additional_data + offset), (void*)(&frame_no), sizeof(frame_no));  // copy the frame number to the AD
    offset += sizeof(frame_no);

    memcpy((void*)(additional_data + offset), (void*)nonce, NONCE_SIZE);  // copy the nonce to the AD
    return decrypt_frame_ad_buf(key, additional_data, encrypted_frame, tag, out);
}

int decrypt_subscription_update(const uint8_t kdk[CHACHA_KEY_SIZE],
                                const subscription_update_packet_t* update,
                                subscription_t* sub) {
    // derive the key using the KDK
    uint32_t info = DECODER_ID;
    uint8_t derived_key[CHACHA_KEY_SIZE];

    if (hkdf_derive_key(kdk, (uint8_t*)(&info), sizeof(info), update->nonce, NONCE_SIZE, derived_key) != 0) {
        return ERROR;
    }

    key_entry_packet_t keys[MAX_KEYS_PER_SUBSCRIPTION];  // might want to change this to just the maximum # of keys

    int ret;

    if ((ret = chacha20_decrypt(derived_key,
                                update->encrypted_keys,
                                update->nkeys * sizeof(key_entry_packet_t),
                                update->tag,
                                (uint8_t*)(&(update->chan)),
                                33,
                                update->nonce,
                                (uint8_t*)keys)) != SUCCESS) {
        return ret;
    }
    sub->active = true;
    sub->frame_start = update->frame_start;
    sub->frame_end = update->frame_end;
    sub->nkeys = update->nkeys;
    sub->chan = update->chan;
    sub->stk_sz = 0;
    // Clear the old keys
    memset(sub->keys, 0, MAX_KEYS_PER_SUBSCRIPTION * sizeof(key_entry_t));
    memset(sub->stk, 0, ROOT_KEY_LEVEL * sizeof(key_entry_t));
    // Copy the keys
    for (int i = 0; i < sub->nkeys; i++) {
        sub->keys[i].frame_start = keys[i].frame_start;
        sub->keys[i].level = keys[i].level;
        memcpy(&sub->keys[i].key, &keys[i].key, 32);
    }

    return SUCCESS;
}

int ecdsa_verify(const uint8_t* in,
                 size_t len,
                 const uint8_t sig[ECDSA_SIGNATURE_SIZE],
                 const uint8_t pub[CRYPTO_ECC_KEY_SIZE]) {
    ecc_key eccKey;
    mp_int r, s;
    if (wc_ecc_init(&eccKey) < 0) {
        return ERROR;
    }

    if (mp_init(&r) != MP_OKAY) {
        wc_ecc_free(&eccKey);
        return ERROR;
    }
    if (mp_init(&s) != MP_OKAY) {
        mp_clear(&r);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    if (wc_ecc_import_unsigned(&eccKey, pub + 1, pub + 1 + CRYPTO_ECC_KEY_SIZE / 2, NULL, ECC_CURVE) != 0) {
        mp_clear(&r);
        mp_clear(&s);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    if (eccKey.type != ECC_PUBLICKEY) {
        mp_clear(&r);
        mp_clear(&s);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    mp_read_unsigned_bin(&r, sig, ECDSA_SIGNATURE_SIZE / 2);
    mp_read_unsigned_bin(&s, sig + ECDSA_SIGNATURE_SIZE / 2, ECDSA_SIGNATURE_SIZE / 2);
    
    uint8_t hash[SHA256_DIGEST_SIZE];
    int res = 0;
    if (wc_Sha256Hash(in, len, hash) != 0 ||
        wc_ecc_verify_hash_ex(&r, &s, hash, SHA256_DIGEST_SIZE, &res, &eccKey) != MP_OKAY) {
        mp_clear(&r);
        mp_clear(&s);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&eccKey);
    if (res != 1) {
        return ECDSA_VERIFY_ERROR;
    }
    return SUCCESS;
}

int ecdsa_verify_sha256hash(const uint8_t hash[SHA256_DIGEST_SIZE],
                            const uint8_t sig[ECDSA_SIGNATURE_SIZE],
                            const uint8_t pub[CRYPTO_ECC_KEY_SIZE]) {
    ecc_key eccKey;
    mp_int r, s;
    if (wc_ecc_init(&eccKey) < 0) {
        return ERROR;
    }

    if (mp_init(&r) != MP_OKAY) {
        wc_ecc_free(&eccKey);
        return ERROR;
    }
    if (mp_init(&s) != MP_OKAY) {
        mp_clear(&r);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    if (wc_ecc_import_unsigned(&eccKey, pub + 1, pub + 1 + CRYPTO_ECC_KEY_SIZE / 2, NULL, ECC_CURVE) != 0) {
        mp_clear(&r);
        mp_clear(&s);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    if (eccKey.type != ECC_PUBLICKEY) {
        mp_clear(&r);
        mp_clear(&s);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    mp_read_unsigned_bin(&r, sig, ECDSA_SIGNATURE_SIZE / 2);
    mp_read_unsigned_bin(&s, sig + ECDSA_SIGNATURE_SIZE / 2, ECDSA_SIGNATURE_SIZE / 2);
    
    int res = 0;
    if (wc_ecc_verify_hash_ex(&r, &s, hash, SHA256_DIGEST_SIZE, &res, &eccKey) != MP_OKAY) {
        mp_clear(&r);
        mp_clear(&s);
        wc_ecc_free(&eccKey);
        return ERROR;
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&eccKey);
    if (res != 1) {
        return ECDSA_VERIFY_ERROR;
    }
    return SUCCESS;
}

int ed25519_verify(const uint8_t* message,
                   size_t m_length,
                   const uint8_t signature[ED25519_SIGNATURE_SIZE],
                   const uint8_t public_key[ED25519_KEY_SIZE]) {
    ed25519_key ed_key;
    wc_ed25519_init(&ed_key);
    if (wc_ed25519_import_public(public_key, ED25519_KEY_SIZE, &ed_key) != 0) {
        return ERROR;
    }
    int ret;
    int ret2;
    if ((ret2 = wc_ed25519_verify_msg(signature, ED25519_SIGNATURE_SIZE, message, m_length, &ret, &ed_key)) != 0) {
        if (ret2 == SIG_VERIFY_E) {
            return ED25519_VERIFY_ERROR;
        }
        return ERROR;
    }
    if (ret != 1) {
        return ERROR;
    }

    return SUCCESS;
}

int hkdf_derive_key(const uint8_t kdk[CHACHA_KEY_SIZE],
                    const uint8_t* info,
                    size_t info_length,
                    const uint8_t* salt,
                    uint8_t salt_length,
                    uint8_t* out) {
    // derive the key using the KDK
    int ret;
    if ((ret = wc_HKDF(WC_SHA256,
                       kdk,
                       CHACHA_KEY_SIZE,
                       salt,
                       salt_length,
                       info,
                       info_length,
                       out,
                       CHACHA_KEY_SIZE)) != 0) {
        return ERROR;
    }
    return SUCCESS;
}
