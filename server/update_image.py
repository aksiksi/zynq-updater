import os
import struct
import binascii

import sha3

def convert_binary(b):
    """Convert a binary value (byte array) to a readable hex string."""
    return binascii.hexlify(b).decode()

class UpdateImage:
    """
        Represents an update image defined by a custom binary image format.

        The following description applies to the case of the Zynq, but can be generalized.

        Input: BOOT.bin, image.ub, app (32-bit ARM ELF)
        Output: update image

        Update image format:

            Header (76 bytes):
            
                4 bytes        4 bytes       4 bytes                   64 bytes
            -------------------------------------------------------------------------------------
            | len(BOOT.bin) | len(image.ub) | len(app) | Keccak512(BOOT.bin || image.ub || app) |
            -------------------------------------------------------------------------------------
            
            Body (variable bytes):

            -----------------------------
            | BOOT.bin | image.ub | app |
            -----------------------------

        Methods:
            - build: given input files, builds an update image as defined above, and returns SHA-3 hash of the image
            - read_header: reads in an update image and returns its header information
    """        
    def build(self, inputs=['BOOT.bin', 'image.ub', 'app'], output_path='output_image.bin'):
        """
            Builds an output image following format defined above and writes it to `output_path`.

            Arguments: 
                - inputs: list of input file paths -> (list of string)
                - output_path: full (or relative) path to write output file to -> (string)
            
            Returns: the SHA-3 hash of the combined image.
        """
        # Get length of each input file in bytes
        lengths = [os.path.getsize(each) for each in inputs]

        # Create output image file on disk
        with open(output_path, 'wb') as output_image:
            # Write output image header
            self.write_header(output_image, lengths)

            # Write image body and body hash, return hash
            hash = self.write_body(output_image, inputs, lengths)

        return hash

    def read_header(self, image_path, num_fields=3):
        """
            Reads in an update image and returns its header contents.

            Arguments:
                - image_path: path to update image -> (string)
                - num_fields: number of length fields in the header -> (int)
            
            Returns: list of header fields as (ints) for the lengths, with the last element a hash in binary format
        """
        header = []
        
        with open(image_path, 'rb') as f:
            for i in range(num_fields):
                # Read in each length field
                b = f.read(4)

                # Unpack to an int
                l = struct.unpack('<I', b)[0]

                header.append(l)

            # Read in the hash (64 bytes)
            hash = f.read(64)
            header.append(hash)
        
        return header

    def write_header(self, output_image, lengths):
        """Write header to output image (without the hash)."""
        # Write input file lengths
        for l in lengths:
            # Convert each int into to 4 bytes in little endian (<) format
            b = struct.pack('<I', l)
            output_image.write(b)

        # Reserve next 64 bytes for SHA-3 hash
        alloc = bytes([0]*64)
        output_image.write(alloc)

    def write_body(self, output_image, inputs, lengths):
        """Write body to output image, and the hash of the body to the header of the output image."""
        # Compute Keccak 512 (slight variation on SHA-3)
        k = sha3.keccak_512()

        # Write each input file to output image while computing hash in parallel
        for each in inputs:
            with open(each, 'rb') as f:
                # Read 1024 bytes from input file and write to output file
                block = f.read(1024)
                output_image.write(block)

                # Update hash computation with the block contents
                k.update(block)

        # Seek back to hash position and write hash to output file
        num_lengths = len(lengths) * 4
        output_image.seek(num_lengths)
        output_image.write(k.digest())

        return k.hexdigest()
