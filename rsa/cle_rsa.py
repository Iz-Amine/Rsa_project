from algo_base import *


# ==================== GÉNÉRATION DE CLÉS RSA ====================
class CleRSA:
    def __init__(self, bits: int = 1024):
        """
        Génère une paire de clés RSA
        """
        print(f"Génération de clés RSA de {bits} bits...")
        
        # Génération de deux nombres premiers p et q
        print("Génération de p...")
        p = generer_nombre_premier(bits // 2)
        print(f"p généré (premier {bits//2} bits)")
        
        print("Génération de q...")
        q = generer_nombre_premier(bits // 2)
        print(f"q généré (premier {bits//2} bits)")
        
        # Calcul de n et phi(n)
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        
        print(f"n = p * q calculé ({bits} bits)")
        
        # Génération de e
        print("Génération de l'exposant public e...")
        self.e = generer_e_cryptographique(self.phi)
        print(f"e = {self.e}")
        
        # Calcul de d (clé privée)
        print("Calcul de l'exposant privé d...")
        self.d = inverse_modulaire(self.e, self.phi)
        
        print("Clés générées avec succès!\n")
        print(f"Clé publique  : (e={self.e}, n={self.n})")
        print(f"Clé privée    : (d={self.d}, n={self.n})")
    
    def obtenir_cle_publique(self) -> Tuple[int, int]:
        """Retourne (e, n)"""
        return (self.e, self.n)
    
    def obtenir_cle_privee(self) -> Tuple[int, int]:
        """Retourne (d, n)"""
        return (self.d, self.n)
