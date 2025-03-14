from encoder import *

def main():
    # create values for decoder tests
    key = bytes.fromhex("02a943ba302de0112c175a6f9e104bcbf4dd6bc9deff839699da8a383f976284")
    frame_num = 0
    frame_data = b'apple\0'
    channel_num = 5
    nonce = b'\xc3\x26\x6c\x7b\xe8\x14\x02\x3c\xae\x9b\x8e\x2c'
    encrypted_frame, nonce, tag, ad, frame_key = encryptFrame(frame_num, key, frame_data, channel_num, nonce=nonce)
    print(f"Key: {frame_key.hex()}\nEncrypted frame: {encrypted_frame.hex()}\nNonce: {nonce.hex()}\nTag: {tag.hex()}\nAD: {ad.hex()}\nPlaintext: {frame_data.hex()}\n\n")
    print((ad + encrypted_frame + tag).hex())

main()
