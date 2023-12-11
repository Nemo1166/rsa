from PIL import Image
import base64
import io
from Crypto.PublicKey import RSA

from rsa import RSADecryptor, RSAEncryptor

class ImageConverter:
    @staticmethod
    def image_to_base64(image: Image.Image, fmt='png') -> str:
        output_buffer = io.BytesIO()
        image.save(output_buffer, format=fmt)
        byte_data = output_buffer.getvalue()
        base64_str = base64.b64encode(byte_data).decode('utf-8')
        return base64_str

    @staticmethod
    def base64_to_image(base64_str: str) -> Image.Image:
        byte_data = base64.b64decode(base64_str)
        image_data = io.BytesIO(byte_data)
        image = Image.open(image_data)
        return image

class ImageEncryptor(RSAEncryptor, ImageConverter):
    def __init__(self, public_key_path: str) -> None:
        super().__init__(public_key_path)

    def encrypt_image(self, image: Image.Image) -> str:
        image_base64 = self.image_to_base64(image)
        encrypted_image_base64 = self.encrypt(image_base64)
        return encrypted_image_base64

class ImageDecryptor(RSADecryptor, ImageConverter):
    def __init__(self, private_key_path: str) -> None:
        super().__init__(private_key_path)

    def decrypt_image(self, encrypted_image_base64: str) -> Image.Image:
        decrypted_image_base64 = self.decrypt(encrypted_image_base64)
        return self.base64_to_image(decrypted_image_base64)

class ImageCrypto(ImageEncryptor, ImageDecryptor):
    def __init__(self, public_key_path: str, private_key_path: str) -> None:
        with open(private_key_path, "r") as private_key_file:
            self.private_key = RSA.import_key(private_key_file.read())
        with open(public_key_path, "r") as public_key_file:
            self.public_key = RSA.import_key(public_key_file.read())

# Example usage
if __name__=="__main__":
    public_key_path = "./key/sd.pub"
    private_key_path = "./key/sd.key"

    image = Image.open("./test.jpg")

    rsa_image_encryptor = ImageCrypto(public_key_path, private_key_path)
    encrypted_image = rsa_image_encryptor.encrypt_image(image)
    print(f"Encrypted image: {encrypted_image}")
    decrypted_image = rsa_image_encryptor.decrypt_image(encrypted_image)
    decrypted_image.show()