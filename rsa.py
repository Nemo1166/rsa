from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSAEncryptor:
    def __init__(self, public_key_path, private_key_path):
        with open(public_key_path, "r") as public_key_file:
            self.public_key = RSA.import_key(public_key_file.read())
        with open(private_key_path, "r") as private_key_file:
            self.private_key = RSA.import_key(private_key_file.read())

    def encrypt(self, message):
        cipher = PKCS1_OAEP.new(self.public_key)
        # Convert message to bytes
        message_bytes = message.encode()
        # Split message into chunks of 190 bytes
        chunk_size = 200
        chunks = [message_bytes[i:i+chunk_size] for i in range(0, len(message_bytes), chunk_size)]
        # Encrypt each chunk and concatenate the results
        encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
        encrypted_message = b"".join(encrypted_chunks)
        # Encode the encrypted message in base64
        return base64.b64encode(encrypted_message).decode()

    def decrypt(self, encrypted_message):
        cipher = PKCS1_OAEP.new(self.private_key)
        # Decode the encrypted message from base64
        encrypted_message_bytes = base64.b64decode(encrypted_message)
        # Split encrypted message into chunks of 256 bytes
        chunk_size = 256
        chunks = [encrypted_message_bytes[i:i+chunk_size] for i in range(0, len(encrypted_message_bytes), chunk_size)]
        # Decrypt each chunk and concatenate the results
        decrypted_chunks = [cipher.decrypt(chunk) for chunk in chunks]
        decrypted_message = b"".join(decrypted_chunks)
        # Convert decrypted message to string
        return decrypted_message.decode()


# Example usage
if __name__=="__main__":
    public_key_path = "./key/sd.pub"
    private_key_path = "./key/sd.key"
    message = "Hello, world!"*100

    encryptor = RSAEncryptor(public_key_path, private_key_path)
    encrypted_message = encryptor.encrypt(message)
    print(f"Encrypted message: {encrypted_message}")
    decrypted_message = encryptor.decrypt(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")
