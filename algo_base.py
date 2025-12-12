import random
from typing import Tuple

# ==================== ALGORITHMES DE BASE ====================

def pgcd_euclide(a: int, b: int) -> int:
    """
    Algorithme d'Euclide pour calculer le PGCD
    """
    while b != 0:
        a, b = b, a % b
    return a

def euclide_etendu(a: int, b: int) -> Tuple[int, int, int]:
    """
    Algorithme d'Euclide étendu
    Retourne (pgcd, x, y) tel que a*x + b*y = pgcd
    """
    if b == 0:
        return a, 1, 0
    
    pgcd, x1, y1 = euclide_etendu(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    
    return pgcd, x, y

def inverse_modulaire(e: int, phi: int) -> int:
    """
    Calcule l'inverse modulaire de e modulo phi
    """
    pgcd, x, y = euclide_etendu(e, phi)
    
    if pgcd != 1:
        raise ValueError("L'inverse modulaire n'existe pas")
    
    return x % phi

def exponentiation_rapide(base: int, exposant: int, modulo: int) -> int:
    """
    Exponentiation modulaire rapide : calcule (base^exposant) mod modulo
    """
    resultat = 1
    base = base % modulo
    
    while exposant > 0:
        if exposant % 2 == 1:
            resultat = (resultat * base) % modulo
        exposant = exposant >> 1
        base = (base * base) % modulo
    
    return resultat

# ==================== TEST DE PRIMALITÉ ====================

def test_miller_rabin(n: int, k: int = 5) -> bool:
    """
    Test de primalité de Miller-Rabin
    k : nombre d'itérations (plus k est grand, plus le test est fiable)
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Écrire n-1 comme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Témoin de Miller-Rabin
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = exponentiation_rapide(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = exponentiation_rapide(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generer_nombre_premier(bits: int) -> int:
    """
    Génère un nombre premier de 'bits' bits
    """
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # S'assurer que le MSB et LSB sont à 1
        
        if test_miller_rabin(n):
            return n

# ==================== GÉNÉRATION DE e ====================

def generer_e_cryptographique(phi: int, min_bits: int = 16) -> int:
    """
    Génère un exposant public e cryptographiquement acceptable
    
    Critères:
    - e doit être premier avec phi(n)
    - e doit être suffisamment grand (> 2^min_bits)
    - Généralement e = 65537 (2^16 + 1) est utilisé en pratique
    """
    # Valeur couramment utilisée : 65537 (nombre de Fermat F4)
    e_standard = 65537
    
    if e_standard < phi and pgcd_euclide(e_standard, phi) == 1:
        return e_standard
    
    # Sinon, générer un e aléatoire
    min_value = 2 ** min_bits
    max_value = phi - 1
    
    if min_value >= max_value:
        min_value = 3
    
    tentatives = 0
    max_tentatives = 10000
    
    while tentatives < max_tentatives:
        e = random.randrange(min_value, max_value, 2)  # Nombre impair
        
        if pgcd_euclide(e, phi) == 1 and test_miller_rabin(e):
            return e
        
        tentatives += 1
    
    raise ValueError("Impossible de générer un e valide")