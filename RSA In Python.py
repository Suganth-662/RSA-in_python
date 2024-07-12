import random
import time

# RSA-related functions
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def is_prime(n, k=10):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=128):
    p = generate_prime_candidate(length)
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def generate_keypair(bits):
    p = generate_prime_number(bits // 2)
    q = generate_prime_number(bits // 2)
    while p == q:
        q = generate_prime_number(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        e = random.randrange(2, phi)
        while gcd(e, phi) != 1:
            e = random.randrange(2, phi)
    
    d = modinv(e, phi)
    
    return ((e, n), (d, n)), p, q

def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    ciphertext_int = pow(plaintext_int, e, n)
    return ciphertext_int

def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big')
    return plaintext

# SPECK-related functions
def rotate_right(x, r, word_size):
    return ((x >> r) | (x << (word_size - r))) & ((1 << word_size) - 1)

def rotate_left(x, r, word_size):
    return ((x << r) | (x >> (word_size - r))) & ((1 << word_size) - 1)

def speck_round(x, y, k, word_size):
    x = rotate_right(x, 8, word_size)
    x = (x + y) & ((1 << word_size) - 1)
    x = x ^ k
    y = rotate_left(y, 3, word_size)
    y = y ^ x
    return x, y

def expand_key(key, rounds, word_size):
    l = key[2:]
    k = [key[1]]

    for i in range(rounds - 1):
        l.append((rotate_right(l[i], 8, word_size) + k[i]) & ((1 << word_size) - 1) ^ i)
        k.append(k[i] + l[i + 2] & ((1 << word_size) - 1) ^ i)
    
    return k

def speck_encrypt(plaintext, key_schedule, word_size):
    x, y = plaintext
    for k in key_schedule:
        x, y = speck_round(x, y, k, word_size)
    return x, y

def speck_decrypt(ciphertext, key_schedule, word_size):
    x, y = ciphertext
    for k in reversed(key_schedule):
        y = y ^ x
        y = rotate_right(y, 3, word_size)
        x = x ^ k
        x = (x - y) & ((1 << word_size) - 1)
        x = rotate_left(x, 8, word_size)
    return x, y

def random_key(word_size, key_words):
    return [random.getrandbits(word_size) for _ in range(key_words)]

def pad_data(data, block_size):
    pad_len = block_size - len(data)
    return data + b'\x00' * pad_len

def speck128_256_encrypt_decrypt(input_data):
    word_size = 64
    key_words = 4
    rounds = 34
    block_size = 16  # 128 bits

    if len(input_data) < block_size:
        input_data = pad_data(input_data, block_size)

    key = random_key(word_size, key_words)
    key_schedule = expand_key(key, rounds, word_size)

    plaintext = (int.from_bytes(input_data[:8], 'big'), int.from_bytes(input_data[8:], 'big'))

    ciphertext = speck_encrypt(plaintext, key_schedule, word_size)

    decrypted_text = speck_decrypt(ciphertext, key_schedule, word_size)

    return key, plaintext, ciphertext, decrypted_text

def calculate_throughput(data_size, time_taken):
    throughput = data_size / time_taken
    return throughput

# Main execution
start_time = time.time()

# RSA keypair generation
keypair, p, q = generate_keypair(256)
public_key, private_key = keypair

# Get input data
#input_data = input("Enter the data to be encrypted: ").encode('utf-8')
input_data = "Power - 5000w".encode('utf-8')
# SPECK encryption
key, plaintext, ciphertext, decrypted_text = speck128_256_encrypt_decrypt(input_data)

# Print results in specified order

# Print p and q
print(f"Prime p: {p}")
print(f"Prime q: {q}")

# Print Public and Private keys
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")

# Print input data
print(f"Input Data: {input_data}")

# Print plaintext for SPECK
plaintext_text = f'{plaintext[0]:016x}{plaintext[1]:016x}'
print(f"Plaintext for Speck (single text): {plaintext_text}")
print("Plaintext (64-bit blocks):")
print(f"Plaintext part 1: {plaintext[0]:016x}")
print(f"Plaintext part 2: {plaintext[1]:016x}")

# Print key used for SPECK
key_text = ''.join(f'{k:016x}' for k in key)
print(f"Key used for Speck (single text): {key_text}")
print("Key (64-bit blocks):")
for i, k in enumerate(key):
    print(f"Key part {i}: {k:016x}")

# Print ciphertext of SPECK
ciphertext_text = f'{ciphertext[0]:016x}{ciphertext[1]:016x}'
print(f"Ciphertext of Speck (single text): {ciphertext_text}")
print("Ciphertext (64-bit blocks):")
print(f"Ciphertext part 1: {ciphertext[0]:016x}")
print(f"Ciphertext part 2: {ciphertext[1]:016x}")

# Convert the key to bytes for RSA encryption
key_bytes = b''.join(k.to_bytes(8, byteorder='big') for k in key)

# RSA encryption of the key
encrypted_key = rsa_encrypt(public_key, key_bytes)
print(f"Encrypted key of Speck by RSA: {encrypted_key}")

# RSA decryption of the key
decrypted_key_bytes = rsa_decrypt(private_key, encrypted_key)
decrypted_key = [int.from_bytes(decrypted_key_bytes[i:i+8], byteorder='big') for i in range(0, len(decrypted_key_bytes), 8)]
decrypted_key_text = ''.join(f'{k:016x}' for k in decrypted_key)
print(f"Decrypted key of Speck by RSA (single text): {decrypted_key_text}")
print("Decrypted key (64-bit blocks):")
for i, k in enumerate(decrypted_key):
    print(f"Decrypted key part {i}: {k:016x}")

# SPECK decryption with the decrypted key
key_schedule_decrypted = expand_key(decrypted_key, 34, 64)
decrypted_text_final = speck_decrypt(ciphertext, key_schedule_decrypted, 64)
decrypted_bytes_final = decrypted_text_final[0].to_bytes(8, 'big') + decrypted_text_final[1].to_bytes(8, 'big')
print(f"Decrypted text by using the key from RSA via Speck (single text): {decrypted_bytes_final.hex()}")
print("Decrypted text (64-bit blocks):")
print(f"Decrypted text part 1: {decrypted_text_final[0]:016x}")
print(f"Decrypted text part 2: {decrypted_text_final[1]:016x}")
print(f"Decrypted text (as string): {decrypted_bytes_final.decode('utf-8', 'ignore')}")

end_time = time.time()
runtime = end_time - start_time

# Throughput calculation
data_size_bits = len(input_data) * 8  # in bits
throughput = calculate_throughput(data_size_bits, runtime)
print(f"Total time taken: {runtime:.4f} seconds")
print(f"Throughput: {throughput:.2f} bits per second")