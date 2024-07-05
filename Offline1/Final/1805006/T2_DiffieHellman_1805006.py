import random

def generate_kbit_prime(k):
    while True:
        p = random.getrandbits(k)
        p|=1<<k-1
        if p % 2 == 0:
            p += 1
        if is_prime(p):
            return p


def is_prime(n, k=20):
    # Base Cases:
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    
    # Trivial Even non-prime:
    if n % 2 == 0:
        return False
    
    
    # n-1 = 2^s * d 
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d = d >> 1

    # Miller-Rabin Test:
    for i in range(k):
        a = random.randint(2, n - 2)
        x = modular_exponent(a, d, n)
        for j in range(s):
            y = modular_exponent(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                return False
            x = y
        if y != 1:
            return False
    return True


def generate_kbit_safe_prime(k):
    while True:
        q = generate_kbit_prime(k-1)
        if is_prime(2*q+1):
            return 2*q+1
        
        
def generate_primitive_root_safe_prime(p, min, max):
    q=p>>1
    if min == 1:
        min+=1
    if max == p-1:
        max-=1
    while True:
        g = random.randint(min, max)
        if modular_exponent(g,2,p) == 1:
            continue
        if modular_exponent(g,q,p) == 1:
            continue
        return g
    
    

def modular_exponent(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent >> 1
    return result

generate_kbit_safe_prime(128)