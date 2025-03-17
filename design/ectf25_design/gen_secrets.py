"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import json
import os
from pathlib import Path
from secrets import token_bytes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from loguru import logger

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """

    # we need root key, pub/priv key for subscription signing
    keys = Ed25519PrivateKey.generate()
    
    private_key = keys
    public_key = keys.public_key()
    
    # create emergency key
    root_keys = [{
        "channel_num": 0,
        "root_key": token_bytes(32).hex()
    }]

    # generate a root key per channel
    for channel in channels:
        root_keys.append({
            "channel_num": channel,
            "root_key": token_bytes(32).hex()
        })

    public_key_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sub_kdk = token_bytes(32).hex()

    secrets = {
        # keys for subscription signing
        "private_key": private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        "public_key": public_key_hex,
        # key for encrypted subscriptions, to be used with the KDF
        "subscription_kdk": sub_kdk,
        # root key for frame encryption
        "root_keys": root_keys
    }

    pub_as_bytes = []
    for i in range(0, len(public_key_hex), 2):
        pub_as_bytes += (public_key_hex[i:i+2],)

    emergency_as_bytes = []
    for i in range(0, len(root_keys[0]['root_key']), 2):
        emergency_as_bytes += (root_keys[0]['root_key'][i:i+2],)

    subscription_kdk_as_bytes = []
    for i in range(0, len(sub_kdk), 2):
        subscription_kdk_as_bytes += (sub_kdk[i:i+2],)

    decoder_file = "\
#ifndef SECRETS_H\n#define SECRETS_H\n\
#include <stdint.h>\n\
const uint8_t ED25519_PUBLIC_KEY[] = { 0x" + ', 0x'.join(pub_as_bytes) + " };\n\
const uint8_t SUBSCRIPTION_KDK[] = { 0x" + ', 0x'.join(subscription_kdk_as_bytes) + "};\n\
const uint8_t EMERGENCY_KEY[] = { 0x" + ', 0x'.join(emergency_as_bytes) + " };\n\
#endif\n\
"

    args = parse_args()

    secrets = json.dumps(secrets).encode(encoding='ascii')

    # decoder_secret_path = os.path.realpath(__file__ + '/../../../decoder/inc/secrets.h')
    # raise Exception(os.listdir(path=os.path.realpath('/workdir/')))
    # raise Exception(args)
    
    # if os.path.isdir(__file__ + '/../decoder'):
        # decoder_secret_path = os.path.realpath(__file__ + '/../decoder/inc/secrets.h')
    
    # print(decoder_secret_path)
    # decoder_secret_path = args.secrets_file.with_suffix('.h')
    # with open(decoder_secret_path, "wb" if args.force else "xb") as f:
    #     # dump file for including on the decoder
    #     f.write(decoder_file.encode('ascii'))

    # logger.success(f"Wrote decoder secrets to {decoder_secret_path}")

    return secrets


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)
    # secrets, decoder_file = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    # logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # decoder_secret_path = args.secrets_file.with_suffix('.h')

    # with open(decoder_secret_path, "wb" if args.force else "xb") as f:
        # dump file for including on the decoder
        # f.write(decoder_file.encode('ascii'))

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote encoder secrets to {str(args.secrets_file.absolute())}")
    # logger.success(f"Wrote decoder secrets to {str(decoder_secret_path.absolute())}")


if __name__ == "__main__":
    main()
