from scapy.all import *
from util.WlanLogger import logger

def generate_ack_packet(_sta_interface,_dst_interface):
	logger.info("generate 802.11 acknowledgement packet");
	return _sta_interface.radiotap / Dot11(addr1=_dst_interface.mac_address, subtype=13, type=1) / Dot11Ack();

def send_ack_packet(_src_interface, _dst_interface):
	logger.info("802.11 acknowledgement packet will send");
	packet = generate_ack_packet(_src_interface,_dst_interface)
	_src_interface.send_packet(packet);
