from typing import List
import base64
from algo_base import exponentiation_rapide
from cle_rsa import CleRSA

class RSAChiffrement:
    """
    RSA pédagogique par blocs + Base64.
    Correctifs:
      - pas de perte des 0x00 au déchiffrement
      - récupération exacte du message (longueur conservée)
    """
    def __init__(self, cle: CleRSA, encoding: str = "utf-8"):
        self.cle = cle
        self.encoding = encoding

        # Taille n en octets (bloc chiffré fixe)
        self.longueur_n = (self.cle.n.bit_length() + 7) // 8

        # Taille bloc clair (doit être STRICTEMENT < n)
        self.taille_bloc_clair = self.longueur_n - 1

    def chiffrer_message(self, message: str) -> str:
        # 1) Encodage (ASCII ou UTF-8)
        data = message.encode(self.encoding)

        # 2) Header longueur (4 bytes) pour retirer le padding à la fin
        header = len(data).to_bytes(4, "big")
        payload = header + data

        # 3) Découpage + padding 0x00 sur dernier bloc
        blocs = self._decouper_et_padder(payload, self.taille_bloc_clair)

        # 4) RSA bloc par bloc
        blocs_chiffres = []
        for bloc in blocs:
            m = int.from_bytes(bloc, "big")
            c = exponentiation_rapide(m, self.cle.e, self.cle.n)
            blocs_chiffres.append(c.to_bytes(self.longueur_n, "big"))

        # 5) Base64
        return base64.b64encode(b"".join(blocs_chiffres)).decode("ascii")

    def dechiffrer_message(self, message_chiffre_b64: str) -> str:
        donnees = base64.b64decode(message_chiffre_b64)

        if len(donnees) % self.longueur_n != 0:
            raise ValueError("Ciphertext invalide: taille non multiple d'un bloc RSA")

        blocs_chiffres = [
            donnees[i:i + self.longueur_n]
            for i in range(0, len(donnees), self.longueur_n)
        ]

        # Déchiffrer en blocs clairs de taille FIXE (important)
        blocs_clairs = []
        for bc in blocs_chiffres:
            c = int.from_bytes(bc, "big")
            m = exponentiation_rapide(c, self.cle.d, self.cle.n)
            blocs_clairs.append(m.to_bytes(self.taille_bloc_clair, "big"))

        payload = b"".join(blocs_clairs)

        # Retirer header longueur + padding
        msg_len = int.from_bytes(payload[:4], "big")
        msg_bytes = payload[4:4 + msg_len]
        return msg_bytes.decode(self.encoding)

    @staticmethod
    def _decouper_et_padder(data: bytes, block_size: int) -> List[bytes]:
        blocs = []
        for i in range(0, len(data), block_size):
            bloc = data[i:i + block_size]
            if len(bloc) < block_size:
                bloc += b"\x00" * (block_size - len(bloc))
            blocs.append(bloc)
        return blocs
