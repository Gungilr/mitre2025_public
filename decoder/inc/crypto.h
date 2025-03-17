#ifndef CRYPTO_H
#define CRYPTO_H

#include <string.h>

// debug
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

// required wolfssl includes
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

// crypto related imports
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "status_led.h"
#include "constants.h"
#include "decoder.h"

/**
 * @brief Decrypts a chacha20 encrypted cipher with a key and checks the tag
 * @pre \p key is exactly 32 bytes
 * @pre \p in is at least \p len bytes
 * @pre \p out is a buffer of at least \p len bytes
 * @pre \p ad is at least \p ad_len bytes
 * @pre \p nonce is exactly 12 bytes
 * @post \p out now stores the plaintext
 * @param key the key to be used for decryption
 * @param in a pointer to the input (encrypted) cipher
 * @param len the length of the \p in buffer, and the \p out buffer
 * @param tag the tag to be checked (for authentication)
 * @param ad the additional data to be checked for authenticity
 * @param ad_len the length of \p ad in bytes
 * @param nonce the number used once for chacha
 * @param out the output buffer that should store the decrypted cipher
 * @return SUCCESS on success, ERROR on general error, TAG_ERROR on tag mismatch
 */
int chacha20_decrypt(const uint8_t key[CHACHA_KEY_SIZE],
                     const uint8_t* in,
                     size_t len,
                     const uint8_t tag[TAG_LENGTH],
                     const uint8_t* ad,
                     size_t ad_len,
                     const uint8_t nonce[NONCE_SIZE],
                     uint8_t* out);

/**
 * @brief decrypts a frame with authentication checking, given an additional data that's already in a uint8_t array
 * @pre \p out is at least the same size as \p buf
 * @pre \p tag is a valid tag for the frame
 * @pre \p additional_data is the formatted additional data in the following order:
 *                 4 bytes     8 bytes           12 bytes
 *                ---------------------------------------------
 *                |       |               |                   |
 *                | CH. # |    FRAME #    |       NONCE       |
 *                |       |               |                   |
 *                ---------------------------------------------
 * @post \p out now stores the decrypted frame
 * @param key the key used for decryption
 * @param additional_data the additional data to be used authentication
 * @param encrypted_frame the input buffer with the encrypted frame
 * @param tag the tag used for authentication checking
 * @param out the output buffer that will store the decrypted frame
 * @return SUCCESS on success, and ERROR on general error, and TAG_ERROR on tag mismatch
 */
int decrypt_frame_ad_buf(const uint8_t key[CHACHA_KEY_SIZE],
                         const uint8_t additional_data[sizeof(uint32_t) + sizeof(uint64_t) + NONCE_SIZE],
                         const uint8_t encrypted_frame[CRYPTO_FRAME_SIZE],
                         const uint8_t tag[TAG_LENGTH],
                         uint8_t* out);

/**
 * @brief decrypts a frame with authentication checking
 * @pre \p out is at least the same size as \p buf
 * @pre \p tag is a valid tag for the frame
 * @post \p out now stores the decrypted frame
 * @param key the key used for decryption
 * @param channel_no the channel number of the frame
 * @param frame_no the frame number
 * @param nonce the number used once
 * @param encrypted_frame the input buffer with the encrypted frame
 * @param tag the tag used for authentication checking
 * @param out the output buffer that will store the decrypted frame
 * @return SUCCESS on success, and ERROR on general error, and TAG_ERROR on tag mismatch
 */
int decrypt_frame(const uint8_t key[CHACHA_KEY_SIZE],
                  uint32_t channel_no,
                  uint64_t frame_no,
                  const uint8_t nonce[NONCE_SIZE],
                  const uint8_t encrypted_frame[CRYPTO_FRAME_SIZE],
                  const uint8_t tag[TAG_LENGTH],
                  uint8_t* out);

/**
 * @brief decrypts a subscription using the KDK and the device ID
 * @pre \p update is a valid structured update packet
 * @post the subscription is now stored in \p sub
 * @return SUCCESS on success, ERROR on general error, TAG_ERROR on tag mismatch
 */
int decrypt_subscription_update(const uint8_t kdk[CHACHA_KEY_SIZE],
                                const subscription_update_packet_t* update,
                                subscription_t* sub);

/**
 * @brief verifies the ECDSA signature 
 * @see https://github.com/wolfSSL/wolfssl-examples/blob/master/ecc/
 * @note To understand the verify function: https://www.wolfssl.com/doxygen/group__ECC.html#ga5b1bb1c6ce3f9238c8f23a3e516952bb
 * @param in the signed data to be verified
 * @param len the length of \p in
 * @param sig the signature to be checked against \p data
 * @param pub the public key to be used
 * @return SUCCESS on success, ERROR on error, ECDSA_VERIFY_ERROR on signature verification fail
 */
int ecdsa_verify(const uint8_t* in,
                 size_t len,
                 const uint8_t sig[ECDSA_SIGNATURE_SIZE],
                 const uint8_t pub[CRYPTO_ECC_KEY_SIZE]);

/**
 * @brief verifies the ECDSA signature given the SHA256 hash and signature
 * @param hash the hash to be verfiied
 * @param sig the signature to be checked against \p data
 * @param pub the public key to be used
 * @return SUCCESS on success, ERROR on error, ECDSA_VERIFY_ERROR on signature verification fail
 */
int ecdsa_verify_sha256hash(const uint8_t hash[SHA256_DIGEST_SIZE],
                            const uint8_t sig[ECDSA_SIGNATURE_SIZE],
                            const uint8_t pub[CRYPTO_ECC_KEY_SIZE]);

/**
 * @brief verifies a signed message using ed25519
 * @param message a pointer to the message to be checked
 * @param m_length the length of the message to be checked
 * @param signature an array with the signature to be checked against
 * @param public_key an array with the public key for the signed message
 * @return SUCCESS on success, ERROR on error, ED25519_VERIFY_ERROR on signature verification fail
 */
int ed25519_verify(const uint8_t* message,
                   size_t m_length,
                   const uint8_t signature[ED25519_SIGNATURE_SIZE],
                   const uint8_t public_key[ED25519_KEY_SIZE]);



/**
 * @brief derives a key using HKDF and SHA-256
 * @pre \p out is at least 32 bytes long.
 * @post \p out now stores the derived key.
 * @param kdk the input key to derive other keys from.
 * @param info the additional information to be used to derived the key (e.g., decoder_id).
 * @param info_length the length of \p info in bytes.
 * @param salt the salt to be used.  Probably going to be a nonce of some kind.
 * @param salt_length the length of the \p salt in bytes.
 * @param out a pointer to where the derived key should be stored.
 */
int hkdf_derive_key(const uint8_t kdk[CHACHA_KEY_SIZE],
                    const uint8_t* info,
                    size_t info_length,
                    const uint8_t* salt,
                    uint8_t salt_length,
                    uint8_t* out);

#endif
