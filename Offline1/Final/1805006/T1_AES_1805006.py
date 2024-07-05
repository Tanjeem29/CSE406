import contextlib
import io
from BitVector import *

from BitVector import *
Sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

InvSbox = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

RC = []
R_con = []

AES_modulus = BitVector(bitstring='100011011')



def read_text_from_file(filename):
    try:
        file = open(filename, "r")
        text = file.read()
        file.close()
        return text
    except:
        print("Error reading file")
        return None
    
def blockify_text(text, block_size):
    blocks = []
    for i in range(0, len(text), block_size):
        blocks.append(text[i:i+block_size])
    blocks[-1] = pad_block(blocks[-1], block_size)
    return blocks


def pad_block(block, block_size):
    if len(block) < block_size:
        block += '\x00' * (block_size - len(block))
    return block

def char_to_bitvector(char):
    ascii = ord(char)
    return BitVector(intVal=ascii, size=8)

def byte_to_bitvector(byte):
    return BitVector(intVal=byte, size=8)


def block_to_2d_bitvector_array(block,rows):
    array = []
    for i in range(rows):
        array.append([])
        for j in range(4):
            array[i].append(char_to_bitvector(block[i*4+j]))
    return array

def print_2d_array(array,dim):
    for i in range(dim):
        for j in range(dim):
            print(array[i][j], end=" ")
        print()
        
def print_2d_array_hex(array):
    for i in range(len(array)):
        for j in range(len(array[0])):
            print(array[i][j].get_hex_string_from_bitvector(), end=" ")
        print()
        
def print_1d_array_hex(array):
    for i in range(len(array)):
        print(array[i].get_hex_string_from_bitvector(), end=" ")
    print()
        
def print_2d_array_hex_as_1d(array):
    for i in range(len(array)):
        for j in range(len(array[0])):
            print(array[i][j].get_hex_string_from_bitvector(), end=" ")
    print()

def print_2d_array_transpose_hex_as_1d(array):
    for i in range(len(array)):
        for j in range(len(array[0])):
            print(array[j][i].get_hex_string_from_bitvector(), end=" ")
    print()
            
def make_key(length, key_txt):
    # key_txt = read_text_from_file("key.txt")
    
    # key_txt = read_text_from_file(key_file)
    
    print("Key:\nIn ASCII:",key_txt)
    if len(key_txt) >length:
        key_txt = key_txt[:length]
    key_blck = blockify_text(key_txt, length)
    key_bv = block_to_2d_bitvector_array(key_blck[0], (int)(length/4))
    
    print("In HEX:",end=' ')
    print_2d_array_hex_as_1d(key_bv)
    print()
    
    return key_bv

def string_to_hex(string):
    hex = ""
    for i in range(len(string)):
        hex += "%02X" % ord(string[i])
    return hex
    



# test2()

def transpose(array):
    for i in range(len(array)):
        for j in range(i):
            temp = array[i][j]
            array[i][j] = array[j][i]
            array[j][i] = temp
    return array

def transpose2(array):
    transposed = []
    num_rows = len(array)
    num_cols = len(array[0]) if array else 0

    for j in range(num_cols):
        row = []
        for i in range(num_rows):
            row.append(array[i][j])
        transposed.append(row)

    return transposed


    

def circular_shift_array_left(array, shift):
    array = array[shift:] + array[:shift]
    return array

def circular_shift_array_right(array, shift):
    array = array[-shift:] + array[:-shift]
    return array

def sub_bytes(array, Sbox):
    for i in range(len(array)):
            # print(array[i][j].int_val(), end=" ")
        array[i] = BitVector(intVal=Sbox[array[i].int_val()], size=8)
    return array            

def sub_bytes_2d(array, Sbox):
    for i in range(len(array)):
        for j in range(len(array[0])):
            # print(array[i][j].int_val(), end=" ")
            array[i][j] = BitVector(intVal=Sbox[array[i][j].int_val()], size=8)
    return array 

def inv_sub_bytes_2d(array, invSbox):
    for i in range(len(array)):
        for j in range(len(array[0])):
            # print(array[i][j].int_val(), end=" ")
            array[i][j] = BitVector(intVal=invSbox[array[i][j].int_val()], size=8)
    return array 

    
def calc_round_constants():
    global RC
    global R_con
    RC.append(BitVector(intVal=1, size=8))
    for i in range(1, 15):
        temp = RC[i-1].int_val()
        temp = (temp << 1) ^ (0x11B if (temp & 0x80) else 0)
        RC.append(BitVector(intVal=temp, size=8))
    for i in range(len(RC)):
        R_con.append([])
        R_con[i].append(RC[i])
        R_con[i].append(BitVector(intVal=0, size=8))
        R_con[i].append(BitVector(intVal=0, size=8))
        R_con[i].append(BitVector(intVal=0, size=8))
    

    
calc_round_constants()

def g(k, round):
    # print('-------in g--------')
    # print_1d_array_hex(k)
    k = circular_shift_array_left(k, 1)
    # print_1d_array_hex(k)
    global Sbox
    k = sub_bytes(k, Sbox)
    # print_1d_array_hex(k)
    k=xor_bitvector_arrays(k, R_con[round])
    # print_1d_array_hex(k)
    return k
    
def xor_bitvector_2d_arrays(array1, array2):
    for i in range(len(array1)):
        for j in range(len(array1[0])):
            array1[i][j] = array1[i][j] ^ array2[i][j]
    return array1

def xor_bitvector_arrays(array1, array2):
    result = []
    for i in range(len(array1)):
        result.append (array1[i] ^ array2[i])
    return result


def matrix_multiply_xor(array1, array2):
    rows1 = len(array1)
    cols1 = len(array1[0])
    rows2 = len(array2)
    cols2 = len(array2[0])
    result = []
    for i in range(rows1):
        result.append([])
        for j in range(cols2):
            result[i].append(BitVector(intVal=0, size=8))
            for k in range(cols1):
                result[i][j] ^= array1[i][k].gf_multiply_modular(array2[k][j], AES_modulus, 8)
    return result


def convert_2d_array_to_1d_array(array):
    result = []
    for i in range(len(array)):
        for j in range(len(array[0])):
            result.append(array[i][j])
    return result

def make_keys(bit_num, key_txt):
    key_length = (int)(bit_num/8)
    diff = (int)(key_length/4)
    # rounds = (int)(bit_num/32) + 6
    if key_length == 16:
        rounds = 10
    elif key_length == 24:
        rounds = 8
    elif key_length == 32:
        rounds = 7
    keybv = make_key(key_length, key_txt)
    # print("Round 0:")
    # print_2d_array_hex(keybv)
    # print_2d_array_hex_as_1d(keybv)
    # print(type(keybv[0][0]))
    for i in range(1,rounds+1):
        # print("=====================round================",i,key_length,diff,rounds,len(keybv),(i-1)*diff, (i-1)*diff+(diff-1))
        temp = xor_bitvector_arrays(keybv[(i-1)*diff], g(keybv[(i-1)*diff+(diff-1)], i-1))
        keybv.append(temp)
        for j in range(1,diff):
            temp = xor_bitvector_arrays(keybv[(i-1)*diff+j], keybv[(i-1)*diff+j+(diff-1)])
            keybv.append(temp)
            
        # print("Round ", i, ":")
        # print_2d_array_hex(keybv)
        # print_2d_array_hex_as_1d(keybv[(4*i):(4*i+4)])
        
        # print(len(keybv))
    return keybv
    
    
    

def add_round_key(array, key):
    for i in range(len(array)):
        for j in range(len(array[0])):
            array[i][j] = array[i][j] ^ key[i][j]
    return array


def shift_rows(array):
    for i in range(1,4):
        array[i] = circular_shift_array_left(array[i], i)
    return array
    

def mix_columns(array):
    # result = []
    return matrix_multiply_xor(Mixer, array)



def encrypt_text_block(text_block, key, rounds):
    text_bv = block_to_2d_bitvector_array(text_block,4)
    print_2d_array_hex_as_1d(text_bv)
    text_bv = transpose2(text_bv)
    keys = []
    for i in range(0,rounds+1):
        keys.append(transpose2(key[(i*4):(i*4+4)]))
    
    # print("----------round 0:-----------")
    text_bv = add_round_key(text_bv, keys[0])
    # print_2d_array_hex(text_bv)
    for i in range(1, rounds+1):
        # print("----------round ", i, ":-----------")
        text_bv = sub_bytes_2d(text_bv, Sbox)
        
        # print('++++AfterSubBytes++++')
        # print_2d_array_hex(text_bv)
        
        text_bv = shift_rows(text_bv)
        
        # print('++++AfterShiftRows++++',i,len(keys))
        # print_2d_array_hex(text_bv)
        
        if i != rounds:
            text_bv = mix_columns(text_bv)
            
            # print('++++AfterMixColumns++++')
            # print_2d_array_hex(text_bv)
        
        text_bv = add_round_key(text_bv, keys[i])
        # print('++++AfterAddRoundKey++++')
        # print_2d_array_hex(text_bv)
    return transpose2(text_bv)
    # return text_bv


def get_char_from_bitvector(bitvector):
    return chr(bitvector.intValue())


def get_text_from_a_bitvector_block(block):
    result = ""
    transpose2(block)
    for i in range(len(block)):
        for j in range(len(block[0])):
            result+=(get_char_from_bitvector(block[i][j]))
    return result

def count_layers(lst):
    if not isinstance(lst, list):
        return 0
    elif len(lst) == 0:
        return 1
    else:
        return max(count_layers(item) for item in lst) + 1

def get_text_from_blocks(blocks):
    result = ""
    for i in range(len(blocks)):
        result= result + get_text_from_a_bitvector_block(blocks[i])
    return result

def get_encrypted_text_from_bv_blocks(blocks):
    result = ""
    for i in range(len(blocks)):
        result= result + get_text_from_a_bitvector_block(blocks[i])
    print("In ASCII:", result)
    print()
    return result

def get_decrypted_text_from_bv_blocks(blocks):
    
    result = ""
    for i in range(len(blocks)):
        result= result + get_text_from_a_bitvector_block(blocks[i])
    result = result.rstrip('\x00')
    print("In ASCII:",result)
    return result


def encrypt_text(text, key, type):
    
    print('Plain Text:\nIn ASCII:', text)
    

    rounds = (int(type/32) + 6)
    text_blocks = blockify_text(text,16)
    encrypted_blocks = []
    
    
    print("In HEX:", end=' ')
    for i in range(len(text_blocks)):
        encrypted_blocks.append(encrypt_text_block(text_blocks[i], key, rounds))
    print()
    # encrypted_text = get_text_from_blocks(encrypted_blocks)
    # return encrypted_text
    
    print('Ciphered Text:\nIn HEX:',end=' ')
    for eb in encrypted_blocks:
        print_2d_array_hex_as_1d(eb)
    
    return encrypted_blocks

#write an inverse shift rows function
def inv_shift_rows(array):
    for i in range(1,4):
        array[i] = circular_shift_array_right(array[i], i)
    return array

def inv_mix_columns(array):
    # result = []
    return matrix_multiply_xor(InvMixer, array)
    



def decrypt_text_block(text_block, key, rounds):
    text_bv = block_to_2d_bitvector_array(text_block,4)
    text_bv = transpose2(text_bv)
    # print("Cipher text blocks:")
    # print_2d_array_hex(text_bv)
    keys = []
    for i in range(0,rounds+1):
        keys.append(transpose2(key[((rounds-i)*4):((rounds-i+1)*4)]))
    # print("key:")
    # print_2d_array_hex(key)
    # print("round 0:")
    text_bv = add_round_key(text_bv, keys[0])
    # print_2d_array_hex(text_bv)
    for i in range(1, rounds+1):
        # print("----------round ", i, ":-----------")
        
        text_bv = inv_shift_rows(text_bv)
        # print('++++AfterInvShiftRows++++')
        # print_2d_array_hex(text_bv)
        
        
        text_bv = inv_sub_bytes_2d(text_bv, InvSbox)
        # print('++++AfterInvSubBytes++++')
        # print_2d_array_hex(text_bv)
        
        
        text_bv = add_round_key(text_bv, keys[i])
        # print('++++AfterAddRoundKey++++')
        # print_2d_array_hex(text_bv)
        
        
        if i != rounds:
            text_bv = inv_mix_columns(text_bv)
            
            # print('++++AfterMixColumns++++')
            # print_2d_array_hex(text_bv)
        
        
    return transpose2(text_bv)



def decrypt_text(text, key, type):
    rounds = (int(type/32) + 6)
    text_blocks = blockify_text(text,16)
    # for blk in text_blocks:
    #     transpose2(blk)
    decrypted_blocks = []
    for i in range(len(text_blocks)):
        decrypted_blocks.append(decrypt_text_block(text_blocks[i], key, rounds))
        
        
    print('Deciphered Text:\nIn HEX:', end=' ')
    for db in decrypted_blocks:
        print_2d_array_hex_as_1d(db)
    return decrypted_blocks
    
    
    
def int_to_ASCII_string(x, length):
    bin_str = bin(x)
    bit_count = len(bin_str) - 2  # '0b'
    # x = x << (length - bit_count) # Padding 
    # bin_str2 = bin(x)
    bin_str = bin_str[2:]
    bin_str += '0' * (length - bit_count)
    # print(bin_str)
    # print(bin_str2)
    bin_strs = [bin_str[i:i+8] for i in range(0, len(bin_str), 8)]
    
    # print("length:", length, "bit_count:", bit_count)
    # for b in bin_strs:
    #     print(b, end='')    
    # print()
    
    int_asciis = [int(b, 2) for b in bin_strs]
    char_asciis = [chr(i) for i in int_asciis]
    req_str= ''.join(char_asciis)
    
    # print(len(req_str))
    # print(len(bin_str))
    
    return req_str

def write_text_to_file(file_name, text):
    file = open(file_name, "w")
    file.write(text)
    file.close()
    
    
    
def encrypt(plain_text, key_text, key_length):
    with contextlib.redirect_stdout(io.StringIO()):
        key = make_keys(key_length, key_text)
        encrypted_blocks = encrypt_text(plain_text, key, key_length)
        encrypted_text = get_encrypted_text_from_bv_blocks(encrypted_blocks)
        return encrypted_text
    
def decrypt(encrypted_text, key_text, key_length):
    with contextlib.redirect_stdout(io.StringIO()):
        key = make_keys(key_length, key_text)
        decrypted_blocks = decrypt_text(encrypted_text, key, key_length)
        decrypted_text = get_decrypted_text_from_bv_blocks(decrypted_blocks)
        return decrypted_text