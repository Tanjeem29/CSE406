from T1_AES_1805006 import * 
import time

def test_AES(type, key_txt, text_file):
    
    #Key Schedule
    start_time = time.perf_counter_ns()
    
    key = make_keys(type, key_txt)
    
    end_time = time.perf_counter_ns()
    key_schedule_time = end_time - start_time
    
    txt = read_text_from_file(text_file)
    
    #Encryption:
    start_time = time.perf_counter_ns()
    
    enc_blocks_bv = encrypt_text(txt, key, type)
    cipher_text = get_encrypted_text_from_bv_blocks(enc_blocks_bv)
    
    end_time = time.perf_counter_ns()
    encryptuin_time = end_time - start_time
    
    #Decryption:
    start_time = time.perf_counter_ns()
    
    dec_blocks = decrypt_text(cipher_text, key, type)
    plain_text = get_decrypted_text_from_bv_blocks(dec_blocks)
    
    end_time = time.perf_counter_ns()
    decryption_time = end_time - start_time
    
    print("\nExecution Time Details:")
    print("Key Schedule Time: ", key_schedule_time/1000000,"ms")
    print("Encryption Time: ", encryptuin_time/1000000,"ms")
    print("Decryption Time: ", decryption_time/1000000,"ms")

key_length = int(input("Enter Key Length [128 / 192 / 256]: "))
test_AES(key_length, read_text_from_file("T1_key_1805006.txt"), "T1_text_1805006.txt")

 