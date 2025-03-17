import json
import argparse
from pathlib import Path

def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets.json file to be used",
    )
    return parser.parse_args()

def main():
	args = parse_args()
	secrets = json.loads(args.secrets_file.read())

	pub_as_bytes = []
	for i in range(0, len(secrets['public_key']), 2):
		pub_as_bytes += (secrets['public_key'][i:i+2],)

	emergency_as_bytes = []
	for i in range(0, len(secrets['root_keys'][0]['root_key']), 2):
		emergency_as_bytes += (secrets['root_keys'][0]['root_key'][i:i+2],)

	subscription_kdk_as_bytes = []
	for i in range(0, len(secrets['subscription_kdk']), 2):
		subscription_kdk_as_bytes += (secrets['subscription_kdk'][i:i+2],)

	decoder_file = "\
#ifndef SECRETS_H\n#define SECRETS_H\n\
#include <stdint.h>\n\
const uint8_t ED25519_PUBLIC_KEY[] = { 0x" + ', 0x'.join(pub_as_bytes) + " };\n\
const uint8_t SUBSCRIPTION_KDK[] = { 0x" + ', 0x'.join(subscription_kdk_as_bytes) + "};\n\
const uint8_t EMERGENCY_KEY[] = { 0x" + ', 0x'.join(emergency_as_bytes) + " };\n\
#endif\n\
"
	with open('./inc/secrets.h', "wb") as f:
        # dump file for including on the decoder
		f.write(decoder_file.encode('ascii'))

main()
