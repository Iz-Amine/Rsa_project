import base64
import hashlib
from algo_base import exponentiation_rapide
from cle_rsa import CleRSA

class RSASignature:
    """
    Signature RSA pédagogique (sans padding PKCS#1 / PSS).
    Correction: SHA-256 stable au lieu de hash().
    """
    def __init__(self, cle: CleRSA, encoding: str = "ascii"):
        self.cle = cle
        self.encoding = encoding
        self.longueur_n = (self.cle.n.bit_length() + 7) // 8

    def _hash_to_int(self, message: str) -> int:
        digest = hashlib.sha256(message.encode(self.encoding)).digest()
        h = int.from_bytes(digest, "big")
        return h % self.cle.n

    def signer_message(self, message: str) -> str:
        h = self._hash_to_int(message)
        s = exponentiation_rapide(h, self.cle.d, self.cle.n)
        return base64.b64encode(s.to_bytes(self.longueur_n, "big")).decode("ascii")

    def verifier_signature(self, message: str, signature_b64: str) -> bool:
        h = self._hash_to_int(message)
        s = int.from_bytes(base64.b64decode(signature_b64), "big")
        h_verif = exponentiation_rapide(s, self.cle.e, self.cle.n)
        return h == h_verif
