#ifndef DECODER_H
#define DECODER_H

#include <stdint.h>
#include "constants.h"

typedef struct {
  uint64_t frame_start;
  // level is the number of nodes below this one
  uint8_t level; // len = 1 << level
  uint8_t key[32];
} key_entry_t;

typedef struct {
  uint32_t chan;
  uint8_t active; // a boolean flag
  uint8_t nkeys;
  uint8_t stk_sz;
  uint64_t frame_start;
  uint64_t frame_end;
  key_entry_t keys[MAX_KEYS_PER_SUBSCRIPTION];
  key_entry_t stk[ROOT_KEY_LEVEL];
} subscription_t;

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html

// decrypted frame packet
typedef struct {
    uint32_t channel;
    uint64_t frame_number;
    uint8_t nonce[NONCE_SIZE];
    uint8_t data[FRAME_SIZE + 1];
    uint8_t tag[TAG_LENGTH];
} frame_packet_t;

typedef struct {
    uint64_t frame_start;
    uint8_t level;
    uint8_t key[32];
} key_entry_packet_t;

typedef struct {
    uint8_t signature[ECDSA_SIGNATURE_SIZE];  // signature of the entire update packet
    uint32_t chan;
    uint8_t nkeys;
    uint64_t frame_start;
    uint64_t frame_end;
    uint8_t nonce[NONCE_SIZE];
    uint8_t tag[TAG_LENGTH];
    uint8_t encrypted_keys[MAX_KEYS_PER_SUBSCRIPTION * sizeof(key_entry_packet_t)];  // key_entry_packet_t, but encrypted
} subscription_update_packet_t;

// These structs are just for responding to the host according with the correct format
typedef struct {
    uint32_t channel;
    uint64_t start;
    uint64_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

#define MESSAGE_ALIGNMENT 256
#define MAX_MESSAGE_LEN ((sizeof(subscription_update_packet_t) + (MESSAGE_ALIGNMENT - 1)) & ~(MESSAGE_ALIGNMENT - 1))

#endif
