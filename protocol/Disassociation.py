from scapy.all import *
from util.WlanLogger import logger

def generate_disassoc_packet(_sta_interface,_dst_interface, reason=3):
	logger.debug("generate a disassociation (reason = "+  str(reason) + ") packet");
	return _sta_interface.radiotap / Dot11(addr1=_dst_interface.mac_address , addr2=_sta_interface.mac_address, addr3=_dst_interface.mac_address,subtype=10,type=0)/Dot11Disas(reason=reason);

def send_disassoc_packet(_src_interface, _dst_interface, reason=3):
	packet = generate_disassoc_packet(_src_interface,_dst_interface, reason);
	_src_interface.send_packet(packet);
	logger.debug("send a disassociation (reason = " + str(reason) + ") packet");

if __name__ == "__main__":
	print("\n\n")
	print("")

	
	STA = STA_Interface(ifc_name="wlx9cc9eb21fa6e",ifc_mac="9c:c9:eb:21:fa:6e");
	AP = AP_Interface(bssid="18:ec:e7:5f:a2:04",essid = "Buffalo-A-A200-Open")

	s = Disassociation(STA,AP);
	s.send_disassoc();




