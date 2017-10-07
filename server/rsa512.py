import math
import binascii

import rsa
import rsakeys

class RSA512:
    def __init__(self, pubkey, prvkey=None):
        self.pubkey = pubkey
        self.prvkey = prvkey

    def encrypt(self, plaintext):
        """
            Given a plaintext as a byte string, encrypts the string in a block-by-block fashion
            using PKCS#1 v1.5.

            Returns: ciphertext as byte string
        """
        # Divide plaintext into 53 byte chunks
        CHUNK_SIZE = 53
        num_chunks = int(len(plaintext) / CHUNK_SIZE)
        last_chunk_size = len(plaintext) % CHUNK_SIZE

        ciphertext = []

        for i in range(num_chunks):
            # Encrypt each chunk with public key
            chunk = plaintext[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]
            enc = rsa.encrypt(chunk, self.pubkey)

            # Append to final ciphertext
            ciphertext += enc

        # For last chunk, left pad with size of padding before encrypting
        last_chunk = plaintext[-last_chunk_size:]
        padding = [CHUNK_SIZE-last_chunk_size]*(CHUNK_SIZE-last_chunk_size)
        last_chunk_padded = bytes(padding) + last_chunk
        ciphertext += rsa.encrypt(last_chunk_padded, self.pubkey)

        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        if not self.prvkey:
            raise Exception('No private key means no decryption!')
        
        CHUNK_SIZE = 64
        num_chunks = int(len(ciphertext) / CHUNK_SIZE)

        plaintext = []

        for i in range(num_chunks):
            # Decrypt each chunk with private key
            chunk = ciphertext[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]
            decrypted = rsa.decrypt(chunk, self.prvkey)
            
            # For last chunk, skip padding by using 0th index
            # Recall that chunk is left padded with [PAD_SIZE]*PAD_SIZE
            if i == num_chunks-1:
                pad_size = decrypted[0]
                decrypted = decrypted[pad_size:]

            # Append to final ciphertext
            plaintext += decrypted

        return bytes(plaintext)

def encrypt(infile='testimage.bin', outfile='testimage_enc.bin'):
    """
        Encrypts given file using RSA-512 in a block-by-block fashion.
    """
    pass

def main():
    r = RSA512(rsakeys.GU_PUB, rsakeys.GU_PRV)
    message = b'Hello, world!'
    enc = r.encrypt(message)
    print(enc)
    dec = r.decrypt(enc)
    print(dec)

    # Throws an error because no private key
    r1 = RSA512(rsakeys.D_PUB)
    enc1 = r1.encrypt(message)
    r1.decrypt(enc1)

if __name__ == '__main__':
    main()
