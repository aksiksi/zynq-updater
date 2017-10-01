import os
import struct

import sha3

class PrepareImage:
    """
        Prepares an update image into a custom binary image format.

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
    """
    def __init__(self, inputs=['BOOT.bin', 'image.ub', 'app'], directory='image'):
        self.inputs = [os.path.join(directory, each) for each in inputs]
        
    def prepare(self, output_path='output_image.bin'):
        # Get length of each input file in bytes
        lengths = [os.path.getsize(each) for each in self.inputs]

        # Create output image file on disk
        output_image = open(output_path, 'wb')

        # Write output image header
        self.write_header(output_image, lengths)

        # Write image body and body hash
        self.write_body(output_image, lengths)

    def write_header(self, output_image, lengths):
        # Write input file lengths
        for l in lengths:
            # Convert each int into to 4 bytes in little endian (<) format
            b = struct.pack('>I', l)
            output_image.write(b)

        # Reserve next 64 bytes for SHA-3 hash
        alloc = bytes([0]*64)
        output_image.write(alloc)

    def write_body(self, output_image, lengths):
        # Compute Keccak 512 (slight variation on SHA-3)
        k = sha3.keccak_512()

        # Write each file to output image while computing hash in parallel
        for each in self.inputs:
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
