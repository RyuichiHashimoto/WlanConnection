from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hmac
import hashlib
from scapy.all import hashes,default_backend,chb,hexdump
import struct
from Crypto.Cipher import AES

QUAD = struct.Struct('>Q')

def generate_pmk_by_sha1(SSID,Password):
    """
    :param SSID: string type
    :param Password: string type
    :return:
    """
    return PBKDF2HMAC(algorithm=hashes.SHA1(),length=32,salt=SSID.encode(),iterations=4096,backend=default_backend()).derive(Password.encode())


def generate_ptk(pmk,amac,smac,anounce,snonce):
    ## may be this function is only used when HMAC-SHA1 MIC is used.
    return customPRF512(pmk,amac,smac,anounce,snonce);

def generate_unicast_keys(ptk):
    kck = ptk[:16];
    kek = ptk[16:32];
    tk = ptk[32:48];
    mic_ap_to_sta = ptk[48:56];
    mic_sta_to_ap = ptk[56:64];

    return [kck,kek,tk,mic_ap_to_sta,mic_sta_to_ap];

def customPRF512(key, amac, smac, anonce, snonce):
    """
        Source https://github.com/secdev/scapy/blob/a436560b456cdf77a52fe64049737166edf476a6/scapy/modules/krack/automaton.py#L193
        Source https://stackoverflow.com/questions/12018920/
    """

    A = b"Pairwise key expansion"
    B = b"".join(sorted([amac, smac]) + sorted([anonce, snonce]))

    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) // 160):
        hmacsha1 = hmac.new(key, A + chb(0x00) + B + chb(i), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()

    return R[:blen]

def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    '''
    mainref: https://github.com/kurtbrose/aes_keywrap/blob/master/aes_keywrap.py
    key wrapping as defined in RFC 3394
    http://www.ietf.org/rfc/rfc3394.txt
    '''
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)

    if key_iv != iv:
        raise ValueError("Integrity Check Failed: "+hex(key_iv)+" (expected "+hex(iv)+")")
    return key

def aes_unwrap_key_and_iv(kek, wrapped):
    n = len(wrapped)//8 - 1
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek, AES.MODE_ECB).decrypt
    for j in range(5,-1,-1): #counting down
        for i in range(n, 0, -1): #(n, n-1, ..., 1)
            ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return b"".join(R[1:]), A


if __name__ == "__main__":

    ANonce = b'\xa8\xd5\x04\xca\x01\xc4\x49\x7f\x71\xc1\x15\x7a\x2f\x11\xcf\xd6\xc1\xe2\x1c\x40\xed\xa0\x9a\xe1\x29\x22\xfd\xc9\x86\x71\x44\x6a';
    SNonce = b'\x48\x45\x21\x14\x7b\xad\x22\x96\x8a\x5b\x52\xd8\xb4\x9d\x2d\x89\x6c\x4b\xb1\x2f\x89\x79\x25\xe5\x97\x95\x43\x56\x0d\x5b\x95\x20';
    A_Mac = b'\x18\xec\xe7\x5f\xa2\x00';
    S_Mac = b'\xb0\xca\x68\x21\x38\x61';
    SSID = "Buffalo-G-A200-wpa2"
    Password = "12345678"


    second_packet = b'\x01\x03\x00\x75\x02\x01\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x48\x45\x21\x14\x7b\xad\x22\x96\x8a\x5b\x52\xd8\xb4\x9d\x2d\x89\x6c\x4b\xb1\x2f\x89\x79\x25\xe5\x97\x95\x43\x56\x0d\x5b\x95\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc2\x92\x1a\x0e\xb4\xf5\x64\x70\x7c\xba\x18\x80\x7a\xe0\x5f\xfa\x00\x16\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00'
    second_packet_set_mic_zero = b'\x01\x03\x00\x75\x02\x01\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x48\x45\x21\x14\x7b\xad\x22\x96\x8a\x5b\x52\xd8\xb4\x9d\x2d\x89\x6c\x4b\xb1\x2f\x89\x79\x25\xe5\x97\x95\x43\x56\x0d\x5b\x95\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00'
    ANSWER = b'\xc2\x92\x1a\x0e\xb4\xf5\x64\x70\x7c\xba\x18\x80\x7a\xe0\x5f\xfa';

    pmk = generate_pmk_by_sha1(SSID, Password);
    ptk = generate_ptk(pmk,A_Mac,S_Mac,ANonce,SNonce);
    kck = generate_unicast_keys(ptk)[0];

    dis = hmac.new(kck, second_packet_set_mic_zero,hashlib.sha1).digest()[:16];

    if (ANSWER == dis):
        print("pass");



