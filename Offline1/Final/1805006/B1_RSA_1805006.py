from T2_DiffieHellman_1805006 import *


def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a%b)

    
def generate_p_q(bits):
    p = generate_kbit_prime(bits)
    q = generate_kbit_prime(bits)
    while p == q:
        q = generate_kbit_prime(bits)
    return p, q

def calculate_n(p, q):
    return p*q

def calculate_phi(p, q):
    return (p-1)*(q-1)

def generate_e(phi):
    e = random.randint(2, phi-1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi-1)
    return e

def generate_d(e, phi):
    return modular_inverse(e, phi)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b%a, a)
    # print(b%a, "*", x1,"+",a,"*", y1, "=",gcd)
    x = y1 - (b//a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None
    return x%m

# extended_gcd(59, 17)

def encrypt(plaintext, e, n):
    encrypted_text = ""
    for c in plaintext:
        encrypted_text += str(modular_exponent(ord(c), e, n)) + " "
    return encrypted_text

def decrypt(ciphertext, d, n):
    decrypted_text = ""
    for c in ciphertext.split():
        decrypted_text += chr(modular_exponent(int(c), d, n))
    return decrypted_text

def test(k):
    
    #Alice
    
    pt = "This is a key. A good key."
    p,q = generate_p_q(k)
    n = calculate_n(p, q)
    phi = calculate_phi(p, q)
    e = generate_e(phi)
    
    ## broadcast (e,n) to others. Others will encrypt their messages with e and n
    
    #Bob
    encrypted_text = encrypt(pt, e, n)
    
    ## broadcast encrypted_text to Alice
    
    #Alice
    d=generate_d(e, phi)
    decrypted_text = decrypt(encrypted_text, d, n)
    
    print("p:", p)
    print("q:", q)
    print("n:", n)
    print("phi:", phi)
    print("e:", e)
    print("d:", d)
    print("Plain text:",pt)
    print("Encrypted Test:",encrypted_text)
    print("Decrypted Test:",decrypted_text)

test(int(input("Enter p,q length in bits: ")))


