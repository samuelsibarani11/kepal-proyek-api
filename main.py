from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Function to find GCD (Greatest Common Divisor) using Euclidean Algorithm
def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# Function to check if a number is prime
def is_prime(n: int) -> bool:
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


# AES encryption and decryption helpers
def pad(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()


def unpad(data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_encrypt(key, plaintext):
    iv = b"\x00" * 16  # Initialization vector set to zero
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8")


def aes_decrypt(key, ciphertext):
    iv = b"\x00" * 16  # Initialization vector set to zero
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decoded_data = base64.b64decode(ciphertext)
    plaintext = unpad(decryptor.update(decoded_data) + decryptor.finalize())
    return plaintext.decode("utf-8")


def pad_key(key: str, length: int) -> bytes:
    """Pads or truncates the key to the required length."""
    key_bytes = key.encode("utf-8")
    if len(key_bytes) < length:
        key_bytes += b" " * (length - len(key_bytes))
    elif len(key_bytes) > length:
        key_bytes = key_bytes[:length]
    return key_bytes


# Endpoint untuk GCD dan bilangan prima
@app.post("/number-theory")
async def number_theory(number: int = Form(...)):
    gcd_result = gcd(number, 100)  # GCD of input number and 100 as an example
    prime_status = is_prime(number)

    return {"gcd_result": gcd_result, "prime_status": prime_status}


# Endpoint untuk enkripsi dan dekripsi AES
@app.post("/process")
async def process_file(
    file: UploadFile = None, key: str = Form(None), process_type: str = Form(None)
):
    result = {}

    # Handle file processing (encryption/decryption)
    if file and key:
        file_content = await file.read()
        key_bytes = pad_key(key, 32)  # Ensure the key is 32 bytes (for AES-256)

        if process_type == "encrypt":
            encrypted_data = aes_encrypt(key_bytes, file_content)
            result["result"] = encrypted_data
        elif process_type == "decrypt":
            decrypted_data = aes_decrypt(key_bytes, file_content.decode("utf-8"))
            result["result"] = decrypted_data
        else:
            return JSONResponse(
                content={"error": "Invalid process type"}, status_code=400
            )

    return result


@app.get("/")
def read_root():
    return {"message": "Welcome to AES Encryption API"}
