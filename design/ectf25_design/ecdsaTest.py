from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def generateKeys():
    keys = ec.generate_private_key(ec.SECP256K1())
    print(f"Private key: {keys.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())}")
    print(f"Public key: {keys.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()}")
    return keys

# Takes data then hashes to sign
def signHash(data: bytes, private_key: ec.EllipticCurvePrivateKey):
    hash_func = hashes.SHA256()
    hasher = hashes.Hash(hash_func)
    hasher.update(data)
    digest = hasher.finalize()
    sig = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hash_func)))
    r, s = utils.decode_dss_signature(sig)
    print(f"Hash: {digest.hex()}")
    print(f"Signature: {r.to_bytes(32, byteorder='big').hex()}{s.to_bytes(32, byteorder='big').hex()}")
    return sig

def main():
    data = b'Im seeing signs...\0'
    # keys = generateKeys()
    # signature = signHash(data, keys)
    keys = Ed25519PrivateKey.generate()
    signature = keys.sign(data)

    print(f"Data: {data}, Public Key: {keys.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}, Signature: {signature.hex()}")

main()
