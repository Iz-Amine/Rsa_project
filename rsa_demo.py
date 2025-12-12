from .algo_base import *
from .cle_rsa import CleRSA
from .rsa_chiffrement import RSAChiffrement
from .rsa_signature import RSASignature

# ==================== DÉMONSTRATION ====================

def demonstration_complete():
    print("=" * 70)
    print("DÉMONSTRATION COMPLÈTE DE L'IMPLÉMENTATION RSA")
    print("=" * 70)
    print()
    
    # 1. Génération des clés
    print("ÉTAPE 1 : GÉNÉRATION DES CLÉS RSA")
    print("-" * 70)
    cle = CleRSA(bits=512)  
    print()
    
    # 2. Chiffrement/Déchiffrement
    print("ÉTAPE 2 : CHIFFREMENT ET DÉCHIFFREMENT")
    print("-" * 70)
    chiffrement = RSAChiffrement(cle)
    
    message_original = "Bonjour! Ceci est un message secret pour tester RSA avec des accents: é, à, ç. 🔐"
    print(f"Message original  : {message_original}")
    print()
    
    message_chiffre = chiffrement.chiffrer_message(message_original)
    print(f"Message chiffré (Base64) :")
    print(f"{message_chiffre[:80]}...")
    print()
    
    message_dechiffre = chiffrement.dechiffrer_message(message_chiffre)
    print(f"Message déchiffré : {message_dechiffre}")
    print(f"Vérification      : {message_original == message_dechiffre}")
    print()
    
    # 3. Signature numérique
    print("ÉTAPE 3 : SIGNATURE NUMÉRIQUE")
    print("-" * 70)
    signature_rsa = RSASignature(cle)
    
    message_a_signer = "Ce message doit être authentifié"
    print(f"Message à signer  : {message_a_signer}")
    
    signature = signature_rsa.signer_message(message_a_signer)
    print(f"Signature (Base64): {signature[:60]}...")
    print()
    
    verification = signature_rsa.verifier_signature(message_a_signer, signature)
    print(f"Vérification      : {verification}")
    
    # Test avec message modifié
    message_modifie = message_a_signer + " (modifié)"
    verification_faux = signature_rsa.verifier_signature(message_modifie, signature)
    print(f"Vérif. (modifié)  : {verification_faux}")
    print()
    
    # 4. Tests des algorithmes
    print("ÉTAPE 4 : TESTS DES ALGORITHMES DE BASE")
    print("-" * 70)
    
    # Test Euclide
    a, b = 48, 18
    pgcd = pgcd_euclide(a, b)
    print(f"PGCD({a}, {b}) = {pgcd}")
    
    # Test Euclide étendu
    pgcd, x, y = euclide_etendu(a, b)
    print(f"Euclide étendu: {a}*{x} + {b}*{y} = {pgcd}")
    print(f"Vérification: {a*x + b*y} = {pgcd}")
    
    # Test exponentiation rapide
    base, exp, mod = 2, 10, 1000
    resultat = exponentiation_rapide(base, exp, mod)
    print(f"Exponentiation: {base}^{exp} mod {mod} = {resultat}")
    print(f"Vérification: {pow(base, exp, mod)} = {resultat}")
    print()
    
    print("=" * 70)
    print("DÉMONSTRATION TERMINÉE AVEC SUCCÈS")
    print("=" * 70)

if __name__ == "__main__":
    demonstration_complete()