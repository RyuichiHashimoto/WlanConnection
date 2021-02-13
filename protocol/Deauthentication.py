from scapy.all import *
from util.WlanLogger import logger

def generate_deauth_packet(_sta_interface,_dst_interface,reason=7):
	logger.debug("generate a deauthentication (reason = " + str(reason) + ") packet");
	return _sta_interface.radiotap / Dot11(addr1=_dst_interface.mac_address , addr2=_sta_interface.mac_address, addr3=_dst_interface.mac_address,subtype=12,type=0)/Dot11Deauth(reason=reason);

def send_deauth_packet(_src_interface, _dst_interface, reason=7):
	packet = generate_deauth_packet(_src_interface,_dst_interface, reason);
	_src_interface.send_packet(packet);
	logger.debug("send a deauthentication (reason = " + str(reason) + ") packet");

