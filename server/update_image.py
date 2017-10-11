import os
import sys
import struct
import binascii

import sha3

"""
    Provides functions to build and read an update image defined by a custom binary image format.

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

    Functions:
        - build: given input files, builds an update image as defined above, and returns SHA-3 hash of the image
        - read_header: reads in an update image and returns its header information
"""

def convert_binary(b):
    """Convert a binary value (byte array) to a readable hex string."""
    return binascii.hexlify(b).decode()
       
def build_image(inputs=['BOOT.bin', 'image.ub', 'app'], output_path='output_image.bin'):
    """
        Builds an output image following format defined above and writes it to `output_path`.

        Arguments: 
            - inputs: list of input file paths -> (list of string)
            - output_path: full (or relative) path to write output file to -> (string)
        
        Returns: SHA-3 hash of the combined image
    """
    # Get length of each input file in bytes
    lengths = [os.path.getsize(each) for each in inputs]

    # Create output image file on disk
    with open(output_path, 'wb') as output_image:
        # Write output image header
        write_image_header(output_image, lengths)

        # Write image body and body hash, return hash
        hash = write_image_body(output_image, inputs, lengths)

    return hash

def read_image_header(image_path, num_fields=3):
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

def write_image_header(output_image, lengths):
    """
        Write header to given output image (without the hash).

        Arguments:
            - output_image: output image file -> (file object)
            - lengths: list of lengths of each input file -> (list of int)
    """
    # Write input file lengths
    for l in lengths:
        # Convert each int into to 4 bytes in little endian (<) format
        b = struct.pack('<I', l)
        output_image.write(b)

    # Reserve next 64 bytes for SHA-3 hash
    alloc = bytes([0]*64)
    output_image.write(alloc)

def write_image_body(output_image, inputs, lengths):
    """
        Write body to output image, and the hash of the body to the header of the output image.

        Arguments:
            - output_image: output image file -> (file object)
            - inputs: list of input files -> (list of string)
            - lengths: list of lengths of each input file -> (list of int)

        Returns: SHA-3 hash digest (string)
    """
    # Compute Keccak 512 (slight variation on SHA-3)
    k = sha3.keccak_512()

    # Write each input file to output image while computing hash in parallel
    for each, length in zip(inputs, lengths):
        with open(each, 'rb') as f:
            # Read 1024 bytes from input file and write to output file
            # Keep reading until EOF
            block = f.read(1024)
            
            while block:
                # Write block to output image
                output_image.write(block)

                # Update hash computation with the block contents
                k.update(block)

                # Read next block
                block = f.read(1024)

            # Append some bytes for hash calculation if not multiple of 64 bytes
            # Pad with 0xFF the end
            last_block_size = length % 64
            
            if last_block_size != 0:
                k.update(b'\xFF' * (64 - last_block_size))

    # Seek back to hash position and write hash to output file
    num_lengths = len(lengths) * 4
    output_image.seek(num_lengths)
    output_image.write(k.digest())

    return k.hexdigest()

def main():
    # Get input files from args
    inputs = sys.argv[1:]
    print('Inputs: {0}'.format(inputs))

    # Build an update image
    output = 'output_image.bin'
    build_image(inputs)

    print('Built image: {0}'.format(output))

if __name__ == '__main__':
    main()
