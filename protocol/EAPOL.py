from scapy.all import *
from scapy.layers.ipsec import *
from util.WlanLogger import logger
from util.Cryptography import generate_pmk_by_sha1,generate_ptk,generate_unicast_keys
from concurrent import futures
import hmac
import hashlib
from copy import deepcopy
from util.Cryptography import aes_unwrap_key

BIG_ENDIAN = "big"
LITTLE_ENDIAN = "little"
ENDIAN = BIG_ENDIAN

def four_way_hand_shake(STA,AP,rsnInfo):


    ### receive a 1/4 EAPOL packet.
    first_packet = receive_packet(STA,AP);
    logger.debug("received a 1/4 EAPOL packet");

    ## multithread process start.
    executor = futures.ThreadPoolExecutor(max_workers=2);
    recv_process = executor.submit(receive_packet,STA,AP);

    ## send a 2/4 EAPOL packet.
    anonce = extract_Nonce_From_EAPOL_Header(first_packet[EAPOL]);
    retry_counter = extract_Retry_From_EAPOL_Header(first_packet[EAPOL]);
    second_packet = generate_second_eap_packet(STA,AP,anonce,rsnInfo,retry_counter=retry_counter);
    executor.submit(STA.send_packet,second_packet)
    logger.debug("send a 2/4 EAPOL packet");


    ## recevie a 3/4 EAPOL packet.
    third_packet = recv_process.result()
    logger.debug("received a 3/4 EAPOL packet");

    ## extract the retry counter from the 3/4 EAPOL packet.
    retry_counter = extract_Retry_From_EAPOL_Header(third_packet[EAPOL]);

    ## extract Group transfer key information.
    WPADATA = extract_WPAKeyData_From_EAPOL_Header(third_packet[EAPOL]);
    unraped_WPADATA = aes_unwrap_key(STA.keys[1],WPADATA);
    Length = unraped_WPADATA[1];
    STA.gtk = unraped_WPADATA[2+Length:];

    ## send a 4/4 EAPOL packet.
    fourth_packet = generate_four_eap_packet(STA,AP,retry_counter);
    STA.send_packet(fourth_packet);
    logger.debug("send a 4/4 EAPOL packet");
    #WPA_Key_Info = extract_WPAKeyData_From_EAPOL_Header(third_packet[EAPOL]);
    #aesCipher = AES.new(str(ptk), AES.MODE_ECB)

    ## send a 4/4 EAPOL packet
    ## discriptkey;


def generate_four_eap_packet(STA,AP,retry_counter):
    logger.debug("generate a 4/4 hand-shake packet");

    Radiotap = STA.radiotap;
    Dot11_Header = Dot11(addr1=AP.mac_address, addr2=STA.mac_address, addr3=AP.mac_address, FCfield=0x01, subtype=8,
                         type=2) / Dot11QoS();
    llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    snap_header = SNAP(OUI=0x000000, code=0x888e)
    snonce = b'\x00' * 0x20

    eapol_header = generate_EAPOL_Header(snonce, key_information_=0x030a,kck=STA.keys[0],replay_counter=retry_counter)

    eapol_packet = Radiotap / Dot11_Header / llc_header / snap_header / eapol_header;
    return eapol_packet;


def generate_second_eap_packet(STA,AP,anonce,rsnInfo,retry_counter=0):
    logger.debug("generate a 2/4 hand-shake packet");

    Radiotap = STA.radiotap;
    Dot11_Header = Dot11(addr1=AP.mac_address, addr2=STA.mac_address, addr3=AP.mac_address, FCfield=0x01, subtype=8, type=2) / Dot11QoS();
    llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    snap_header = SNAP(OUI=0x000000, code=0x888e)

    snonce = generate_nonce(32);

    logger.info("generate pmk packet")
    pmk = generate_pmk_by_sha1(AP.essid, AP.password);
    logger.info("generate ptk packet")
    ptk = generate_ptk(pmk,mac2str(AP.mac_address),mac2str(STA.mac_address),anonce,snonce);
    logger.info("generate unicast keys")
    STA.keys = generate_unicast_keys(ptk)
    kck = STA.keys[0];

    eapol_header = generate_EAPOL_Header(snonce,key_information_=0x010a,replay_counter=retry_counter,kck=kck,KeyData=rsnInfo)

    eapol_packet = Radiotap / Dot11_Header / llc_header / snap_header / eapol_header;
    return eapol_packet


def generate_EAPOL_Header(snonce,key_information_,replay_counter,kck=None,KeyData=None):

    ### These packet is set for WPA2-PSK-AES.
    EAP_PACKET = EAPOL(version="802.1X-2001", type="EAPOL-Key");
    key_descriptor_type = 2; ## rsn information
    key_information = key_information_; ## Key mic is set. key information is "AES Cipher, HMAC-SHA1 MIC"
    key_id = 0;
    key_rsc = 0;
    key_length = b'\x00\x10'
    key_iv = b'\x00' * 0x10;
    ####
    key_mic = b'\x00'*0x10;
    payload = b"".join([chb(key_descriptor_type), struct.pack(">H", key_information), key_length]);
    payload += struct.pack(">Q", replay_counter) if isinstance(replay_counter,int)  else replay_counter
    payload += b"".join([snonce, key_iv, struct.pack(">Q", key_rsc), struct.pack(">Q", key_id)]);

    offset_MIC = len(payload);
    payload += key_mic;


    if KeyData is not None:
        payload += struct.pack(">H",len(KeyData));
        payload = payload + raw(KeyData);
    else:
        payload = payload + struct.pack(">H", 0);

    if(kck is not None):
        EAPOL_Header_dummy = EAP_PACKET/Raw(load=payload);
        raw_eapol_header_dummy = raw(EAPOL_Header_dummy);

        mic = hmac.new(kck,raw_eapol_header_dummy,hashlib.sha1).digest()[:16];
        final_payload = payload[:offset_MIC] + mic + payload[offset_MIC+len(mic):];
    else:
        final_payload = payload;

    return EAP_PACKET/Raw(load=final_payload);

def generate_nonce(size):
    return raw(RandBin(size));

def extract_Retry_From_EAPOL_Header(EAPOL_Header):
    return EAPOL_Header.load[5:13];

def extract_Nonce_From_EAPOL_Header(EAPOL_Header):
    return EAPOL_Header.load[13:45]

def extract_KEY_IV_EAPOL_Header(EAPOL_Header):
    return EAPOL_Header.load[45:61];

#def extract_WPA_From_EAPOL_Header(EAPOL_Header):
#    return EAPOL_Header.load[13:45]


def extract_WPAKeyData_From_EAPOL_Header(EAPOL_Header):
    KeyLength_bytes = EAPOL_Header.load[93:95]
    KeyLength_int = int.from_bytes(KeyLength_bytes,ENDIAN);
    return EAPOL_Header.load[95:96+KeyLength_int];

def receive_packet(STA,AP):
    return STA.recv_packet(filter=lambda x: ((x.haslayer(EAPOL))) and (True) and (x[Dot11].addr2 == AP.bssid) and (STA.is_packet_for_me(x)))[0];







if __name__ == "__main__":
    ls(EAPOL)
