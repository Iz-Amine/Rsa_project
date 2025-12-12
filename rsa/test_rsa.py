#!/usr/bin/env python3
"""
Script de test RSA simple pour le terminal
Usage: python test_rsa.py
"""

from algo_base import *
from cle_rsa import CleRSA
from rsa_chiffrement import RSAChiffrement
from rsa_signature import RSASignature

def test_algo_base():
    """Test des algorithmes de base"""
    print("\n[TEST 1] Algorithmes de base")
    print("-" * 40)
    
    # PGCD
    a, b = 48, 18
    pgcd = pgcd_euclide(a, b)
    assert pgcd == 6, f"PGCD échoué: {pgcd} != 6"
    print(f"✓ PGCD({a}, {b}) = {pgcd}")
    
    # Euclide étendu
    pgcd, x, y = euclide_etendu(a, b)
    assert a*x + b*y == pgcd, "Euclide étendu échoué"
    print(f"✓ Euclide étendu: {a}*{x} + {b}*{y} = {pgcd}")
    
    # Exponentiation rapide
    resultat = exponentiation_rapide(2, 10, 1000)
    assert resultat == 24, f"Exponentiation échouée: {resultat} != 24"
    print(f"✓ 2^10 mod 1000 = {resultat}")
    
    # Test primalité
    assert test_miller_rabin(17) == True, "17 devrait être premier"
    assert test_miller_rabin(18) == False, "18 ne devrait pas être premier"
    print(f"✓ Test primalité: 17 premier, 18 non premier")

def test_chiffrement():
    """Test chiffrement/déchiffrement"""
    print("\n[TEST 2] Chiffrement/Déchiffrement")
    print("-" * 40)
    
    cle = CleRSA(bits=512)
    chiffrement = RSAChiffrement(cle)
    
    messages = [
        "Hello",
        "Message test", 
        "Test 123",
        "A" * 100  # Message long
    ]
    
    for msg in messages:
        chiffre = chiffrement.chiffrer_message(msg)
        dechiffre = chiffrement.dechiffrer_message(chiffre)
        assert msg == dechiffre, f"Échec: '{msg}' != '{dechiffre}'"
        print(f"✓ '{msg[:30]}...' OK")

def test_signature():
    """Test signature numérique"""
    print("\n[TEST 3] Signature numérique")
    print("-" * 40)
    
    cle = CleRSA(bits=512)
    signature_rsa = RSASignature(cle)
    
    msg = "Message a signer"
    signature = signature_rsa.signer_message(msg)
    
    # Vérification valide
    assert signature_rsa.verifier_signature(msg, signature) == True
    print(f"✓ Signature valide pour: '{msg}'")
    
    # Vérification invalide
    msg_modifie = msg + " modifie"
    assert signature_rsa.verifier_signature(msg_modifie, signature) == False
    print(f"✓ Signature invalide pour message modifié")

def test_bug_fix():
    """Test correction du bug de génération"""
    print("\n[TEST 4] Génération de nombres premiers")
    print("-" * 40)
    
    for bits in [8, 16, 32]:
        n = generer_nombre_premier(bits)
        assert n.bit_length() == bits, f"Taille incorrecte: {n.bit_length()} != {bits}"
        assert test_miller_rabin(n), f"{n} n'est pas premier"
        print(f"✓ Nombre premier {bits} bits: {n}")

def test_cles_rsa():
    """Test génération et utilisation des clés"""
    print("\n[TEST 5] Génération de clés RSA")
    print("-" * 40)
    
    cle = CleRSA(bits=512)
    e, n = cle.obtenir_cle_publique()
    d, _ = cle.obtenir_cle_privee()
    
    # Vérifier que e*d ≡ 1 (mod phi)
    assert (e * d) % cle.phi == 1, "Clés invalides: e*d != 1 (mod phi)"
    print(f"✓ Clés valides: e={e}, d={d}")
    print(f"✓ n={n} ({n.bit_length()} bits)")

if __name__ == "__main__":
    print("=" * 40)
    print("TESTS RSA - IMPLÉMENTATION PÉDAGOGIQUE")
    print("=" * 40)
    
    try:
        test_algo_base()
        test_bug_fix()
        test_cles_rsa()
        test_chiffrement()
        test_signature()
        
        print("\n" + "=" * 40)
        print("✅ TOUS LES TESTS RÉUSSIS")
        print("=" * 40)
        
    except AssertionError as e:
        print(f"\n❌ ÉCHEC: {e}")
    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()