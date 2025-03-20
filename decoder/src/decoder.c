/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "secrets.h"
// const uint8_t ED25519_PUBLIC_KEY[] = { };
// const uint8_t SUBSCRIPTION_KDK[] = { };
// const uint8_t EMERGENCY_KEY[] = { };

#include "constants.h"

#include "mxc_device.h"
#include "mxc_delay.h"
#include "board.h"

#include "status_led.h"
#include "host_messaging.h"
#include "simple_flash.h"
#include "simple_uart.h"
#include "decoder.h"
#include "crypto.h"

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    subscription_t subscriptions[NUM_SUBSCRIPTIONS];
} flash_entry_t;

flash_entry_t decoder_state;

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/**
 * @brief finds a subscription in the decoder_state global
 * @param chan the channel number to find
 * @param index a pointer to where the index of \p chan in the subscriptions array
 *          of the decoder_state global should be stored. Ignored if NULL.  Will be unchanged if not found.
 * @return NULL if the subscription was not found, or the pointer to the subscription holding \p chan
 */
 subscription_t* subscription_get(uint32_t chan, uint8_t* index) {
    for (uint8_t i = 0; i < NUM_SUBSCRIPTIONS; i++) {
        if (decoder_state.subscriptions[i].chan == chan && decoder_state.subscriptions[i].active) {
            if (index != NULL) {
                *index = i;
            }
            return &(decoder_state.subscriptions[i]);
        }
    }
    return NULL;
}

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(uint32_t chan) {
    // Check if the decoder has has a subscription
    return subscription_get(chan, NULL) != NULL;
}

void key_print(uint8_t key[32]) {
    write_hex(DEBUG_MSG, key, 32);
    print_debug("\n");
}

/**
 * @brief Hashes an intermediate key to give the next key, which will eventually
 * yield a decryption key.
 * 
 * @param key the intermediate key
 * @param salt the salt to use to derive the next key
 * @param digest an output parameter that will store the resulting hash
 */
void key_hash(uint8_t key[32], uint64_t salt, uint8_t digest[32]) {
	Sha256 s;
	wc_InitSha256(&s);
    wc_Sha256Update(&s, key, 32);
	wc_Sha256Update(&s, (byte*)&salt, sizeof(salt));
    wc_Sha256Final(&s, digest);
}

/**
 * @brief Hashes the key to get the next key. Successive calls will eventually reach
 * the key for the given frame.
 * 
 * @param k the current key entry
 * @param frame the frame number whose decryption key we wish to derive
 * @param res an output parameter that will store the next key entry in the
 *        derivation
 */
void key_hash_towards_frame(key_entry_t* k, uint64_t frame, key_entry_t* res) {
    /*
     * The salt is the starting frame number covered by the key entry, which is
     * guaranteed to be unique for the left and right children. It is helpful
     * to think of the frame number's bitstring as deciding which route to take
     * (left vs right) at each level of the tree. Thus, the starting frame
     * number (salt) is the frame number with the lowest "level" bits set to
     * zero.
     * 
     * Note: the salt value was chosen somewhat arbitrarily; it does not matter
     * as long as it is the same for frames under the same subtree, and
     * distinct from the other salt at the same level.
     * 
     * Also note: level is assumed to be positive, since hashing a level 1 key
     * gives us the final key for the frame.
     */
    uint64_t child_level = k->level - 1;
    uint64_t child_frame_start = (frame >> child_level) << child_level;

    // Return a new key entry in the output parameter res
    res->frame_start = child_frame_start;
    res->level = child_level;
    key_hash(k->key, child_frame_start, res->key);
}

/**
 * @brief Returns true if the given key can eventually derive the given frame
 *
 * @param k a key
 * @param frame the frame number we wish to derive decryption keys for
 * @return 1 if k can eventually derive frame, 0 otherwise
 */
int key_covers_frame(key_entry_t* k, uint64_t frame) {
    /*
     * There are two cases: either the key's level is zero, or nonzero. If it's
     * zero, then it's a leaf key so the frame start must equal the given frame
     * number.
     * 
     * If the key's level is nonzero, then frame start must be a power of 2,
     * and everything from frame start to the start of the next level is
     * covered. This means we can ignore the low bits of the frame numbers
     * since they are part of the same subtree.
     * 
     * For example, let's say frame start is 16 and level is 4. In this case,
     * frames 16-31 (0b10000 - 0b11111) are covered by this key, so we can
     * ignore the last 4 bits during the comparison to find whether the
     * provided frame number lies in this range.
     * 
     * Now consider what if level is 3. In this case, frames 16-23
     * (0b10000 - 0b10111) are covered, so we can ignore the last 3 bits during
     * the comparison.
     */
    return (k->frame_start >> k->level) == (frame >> k->level);
}

/**
 * @brief
 * Returns the final decryption key for a particular frame
 *
 * @param chan the satellite channel number
 * @param frame the frame number we wish to decrypt
 * @param key output parameter that will hold the decryption key
 * @return 1 if key was successfully found, 0 otherwise
 */
int key_derive(uint32_t chan, uint64_t frame, uint8_t key[32]) {
    // find subscription
    subscription_t* sub = subscription_get(chan, NULL);
    if (sub == NULL) return 0;


    if (sub->stk_sz == 0 || !key_covers_frame(&sub->stk[0], frame)) {
        // empty stack or stack that doesn't cover our needed frame
        // check for correct key presence in lib
        for (uint8_t i = 0; i < sub->nkeys; i++) {
            if (key_covers_frame(&sub->keys[i&0x7f], frame)) {
                sub->stk[0] = sub->keys[i&0x7f];
                sub->stk_sz = 1;
                goto key_found;
            }
        }
        // no valid key found
        return 0;
    }
    
  key_found:
    // Pop the stack until the key on the top of the stack can be used to derive our frame
    while (!key_covers_frame(&sub->stk[sub->stk_sz - 1], frame)) sub->stk_sz--;

    // Derive keys from the top of the stack until we get the level 0 key
    while (sub->stk[sub->stk_sz - 1].level) {
        key_hash_towards_frame(&sub->stk[sub->stk_sz - 1], frame, &sub->stk[sub->stk_sz]);
        sub->stk_sz++;
    }

    // Ensure we didn't skip an instruction
    if (!sub->active || sub->chan != chan)
        return 0;
    if (sub->stk[sub->stk_sz - 1].level || sub->stk[sub->stk_sz - 1].frame_start != frame)  // right side of or keeps failing!!!
        return 0;

    // Copy the top key in stack to output
    memcpy(key, sub->stk[sub->stk_sz - 1].key, 32);
    return 1;
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels() {
    list_response_t resp;
    uint16_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_state.subscriptions[i].active) {
            resp.channel_info[resp.n_channels].channel = decoder_state.subscriptions[i].chan;
            resp.channel_info[resp.n_channels].start = decoder_state.subscriptions[i].frame_start;
            resp.channel_info[resp.n_channels].end = decoder_state.subscriptions[i].frame_end;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
 */
int update_subscription(uint16_t pkt_len, subscription_update_packet_t *update) {
    if (update->chan == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    // verify the subscription signature, can remove to ensure <500ms runtime
    int status;
    if ((status = ed25519_verify((const uint8_t*)(update) + ED25519_SIGNATURE_SIZE,
                                 pkt_len - ED25519_SIGNATURE_SIZE,
                                 update->signature,
                                 ED25519_PUBLIC_KEY)) != SUCCESS) {
        if (status == ED25519_VERIFY_ERROR) {
            print_error("Failed to update subscription - failed subscription verification\n");
        } else {
            print_error("Failed to update subscription - unable to verify\n");
        }
        return -1;
    }

    uint8_t index;
    // get pointer to subscription
    subscription_t* sub = subscription_get(update->chan, &index);
    if (sub == NULL) {
        for (uint8_t i = 0; i < NUM_SUBSCRIPTIONS; i++) {
            if (!decoder_state.subscriptions[i].active) {
                sub = &decoder_state.subscriptions[i];
                index = i;
                goto sub_found;
            }
        }
        print_error("Failed to update subscription - no available slots\n");
        return -1;

      sub_found: ;
    }

    if (decrypt_subscription_update(SUBSCRIPTION_KDK, update, sub) != SUCCESS) {
        print_error("Error decrypting the subscription.\n");
        return -1;
    }

    uint32_t sub_flash_address = FLASH_STATUS_ADDR + (index * 2) * MXC_FLASH_PAGE_SIZE;
    if (flash_simple_erase_page(sub_flash_address) < 0) {
        print_error("Error erasing page.");
    }
    if (flash_simple_erase_page(sub_flash_address + MXC_FLASH_PAGE_SIZE) < 0) {
        print_error("Error erasing page.");
    }
    if (flash_simple_write(sub_flash_address, &(decoder_state.subscriptions[index]), sizeof(subscription_t) - (MAX_KEYS_PER_SUBSCRIPTION - (decoder_state.subscriptions[index].nkeys & 0x7f)) * sizeof(key_entry_t)) < 0) {  // truncated
        print_error("Could not write subscription to flash");
    }
    char output_buf[128];
    snprintf(output_buf, sizeof(output_buf), "Wrote subscription to flash! decoder_state.first_boot=%x\n", decoder_state.first_boot);
    print_debug(output_buf);

    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful. -1 if data is from unsubscribed channel.
 */
int decode(uint16_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};

    uint32_t chan = new_frame->channel;
    uint64_t frame = new_frame->frame_number;

    print_debug("Checking subscription\n");
    subscription_t *sub = subscription_get(chan, NULL);

    if (chan == EMERGENCY_CHANNEL || (sub != NULL
                                     && frame >= sub->frame_start
                                     && frame <= sub->frame_end)) {
        print_debug("Subscription Valid\n");        
        
        uint8_t decoded_frame[CRYPTO_FRAME_SIZE];
        
        // Either use the emergency channel key, get the correct key, or fail
        uint8_t key[32];
        memcpy(key, EMERGENCY_KEY, sizeof(key));
        if (chan != EMERGENCY_CHANNEL && !key_derive(chan, frame, key)) {
            snprintf(output_buf, sizeof(output_buf), "Decoding frame #%llu failed: could not derive key\n", frame);
            print_error(output_buf);
            return -1;
        }

        if (decrypt_frame(key, chan, frame, new_frame->nonce, new_frame->data, new_frame->tag, decoded_frame)) {
            // error
            snprintf(output_buf, sizeof(output_buf), "Decoding frame #%llu failed: could not decrypt frame\n", frame);
            print_error(output_buf);
            return -1;
        }

        uint16_t decoded_size = *((uint8_t*)(&decoded_frame));
        write_packet(DECODE_MSG, decoded_frame + 1, decoded_size);
        return 0;
    } else {
        STATUS_LED_RED();
        snprintf(output_buf, sizeof(output_buf), "Receiving unsubscribed channel data. # %u. Frame # %llu\n", chan, frame);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
 */
void init() {
    int ret;

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // reconstruct the decoder_state first boot canary
    flash_simple_read(FLASH_FIRST_BOOT_ADDR, &(decoder_state.first_boot), sizeof(decoder_state.first_boot));

    char output_buf[128];
    snprintf(output_buf, sizeof(output_buf), "decoder_state.first_boot = 0x%08x\n", decoder_state.first_boot);
    print_debug(output_buf);

    if (decoder_state.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
         * This data will be persistent across reboots of the decoder. Whenever the decoder
         * processes a subscription update, this data will be updated.
         */
        print_debug("First boot.  Setting flash...\n");

        decoder_state.first_boot = FLASH_FIRST_BOOT;

        memset(decoder_state.subscriptions, 0, sizeof(subscription_t) * MAX_CHANNEL_COUNT);

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            decoder_state.subscriptions[i].active = 0;
            decoder_state.subscriptions[i].frame_start = DEFAULT_CHANNEL_TIMESTAMP;
            decoder_state.subscriptions[i].frame_end = DEFAULT_CHANNEL_TIMESTAMP;
            decoder_state.subscriptions[i].nkeys = 0;
            decoder_state.subscriptions[i].stk_sz = 0;
        }
        if (flash_reset() < 0) {
            print_error("Error erasing flash.");
        }
        if (flash_simple_write(FLASH_FIRST_BOOT_ADDR, &(decoder_state.first_boot), sizeof(decoder_state.first_boot)) < 0) {  // canary
            print_error("Could not write to flash.");
        }
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {  // flash each blank subscription to each of their own 2 pages
            if (flash_simple_write(FLASH_STATUS_ADDR + (i * 2) * MXC_FLASH_PAGE_SIZE, &(decoder_state.subscriptions[i]), sizeof(subscription_t)) < 0) {
                print_error("Could not write to flash.");
            }
        }
    } else {  // we've booted before, read the subscriptions from flash
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {  // read each subscription
            subscription_t sub;
            flash_simple_read(FLASH_STATUS_ADDR + (i * 2) * MXC_FLASH_PAGE_SIZE, &sub, sizeof(subscription_t));
            if (sub.active) {
                memcpy(&(decoder_state.subscriptions[i]), &sub, sizeof(subscription_t));
            }
            flash_simple_read(FLASH_STATUS_ADDR + (i * 2) * MXC_FLASH_PAGE_SIZE, &(decoder_state.subscriptions[i]), sizeof(subscription_t));
        }
    }
}

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[MAX_MESSAGE_LEN];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;
    
    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            snprintf(output_buf, sizeof(output_buf), "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
