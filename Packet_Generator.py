from scapy.layers.eap import EAPOL
from scapy.all import *
import struct
from STA_AP_Interface import STA_Interface,AP_Interface
from protocol.EAPOL import generate_EAPOL_Header
from protocol.Beacon import scan_beacon_packet;
from protocol.ElementTag import extract_tagged_parameter_from_dot11elt
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from util.Cryptography import generate_pmk_by_sha1


def _customPRF512(key, amac, smac, anonce, snonce):
    """Source https://stackoverflow.com/questions/12018920/"""
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





if __name__ == "__main__":
    ANonce = b'\xa8\xd5\x04\xca\x01\xc4\x49\x7f\x71\xc1\x15\x7a\x2f\x11\xcf\xd6\xc1\xe2\x1c\x40\xed\xa0\x9a\xe1\x29\x22\xfd\xc9\x86\x71\x44\x6a';
    SNonce = b'\x48\x45\x21\x14\x7b\xad\x22\x96\x8a\x5b\x52\xd8\xb4\x9d\x2d\x89\x6c\x4b\xb1\x2f\x89\x79\x25\xe5\x97\x95\x43\x56\x0d\x5b\x95\x20';
    A_Mac = b'\x18\xec\xe7\x5f\xa2\x00';
    S_Mac = b'\xb0\xca\x68\x21\x38\x61';

    SSID = "Buffalo-G-A200-wpa2"
    Password = "12345678"

    #pmk = generate_pmk_by_sha1(SSID,Password);
    #ptk = customPRF512(pmk, A_Mac, S_Mac, ANonce, SNonce);
    #kck = ptk[:16];
    snonce = b'\x00' * 0x20;
    print(hexdump(snonce));










    """
    #bytes_second = b"25";
    ifc_name = "wlx9cc9eb21fa6e";
    ifc_mac = "9c:c9:eb:21:fa:6e"
    STA = STA_Interface(ifc_name, ifc_mac);
    AP = AP_Interface(bssid="18:ec:e7:5f:a2:00", essid="Buffalo-G-A200-wpa2");

    beacon_packet = scan_beacon_packet(STA,AP);
    elementTags = extract_tagged_parameter_from_dot11elt(beacon_packet[Dot11Elt]);
    rsninfo = [tag for tag in elementTags if tag.ID == 48][0];
    packet = generate(STA,AP,tag=rsninfo);

    STA.send_packet(packet);


    #print(struct.pack(">H",3));






    #print(bytes_hex(packet))
    """






    #ls(packet)




