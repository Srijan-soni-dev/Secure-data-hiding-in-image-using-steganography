from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# AES encryption
def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

# Encoding the message in an image
def encode_image(image_path, secret_data, output_image_path, key):
    encrypted_data = encrypt_message(secret_data, key)
    message_bin = ''.join(format(ord(char), '08b') for char in encrypted_data)
    image = Image.open(image_path)
    pixels = image.load()
    data_index = 0
    message_length = len(message_bin)

    for i in range(image.size[0]):
        for j in range(image.size[1]):
            pixel = list(pixels[i, j])
            for color in range(3):  # R, G, B
                if data_index < message_length:
                    pixel[color] = pixel[color] & 0b11111110 | int(message_bin[data_index])
                    data_index += 1
            pixels[i, j] = tuple(pixel)
            if data_index >= message_length:
                break
        if data_index >= message_length:
            break

    image.save(output_image_path)
    print(f"Message successfully encoded into {output_image_path}")

# Extracting data from the image
def extract_data_from_image(image_path):
    image = Image.open(image_path)
    pixels = image.load()
    binary_message = ''
    for i in range(image.size[0]):
        for j in range(image.size[1]):
            pixel = pixels[i, j]
            for color in range(3):  # R, G, B
                binary_message += str(pixel[color] & 1)
    encrypted_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
    return encrypted_message

# Decrypting the message
def decrypt_message(encrypted_message, key):
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted_data

# Example usage
key = 'thisisaverysecurekey123'
secret_message = "This is a secret message!"
encode_image('input_image.png', secret_message, 'encoded_image.png', key)
encrypted_message = extract_data_from_image('encoded_image.png')
decrypted_message = decrypt_message(encrypted_message, key)
print(f"Decrypted message: {decrypted_message}")
