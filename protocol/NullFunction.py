from util.WlanLogger import logger
from scapy.all import *


def generate_qos_null_function_packet(_sta_interface,_dst_interface, _FCField):
	logger.debug("generate a QoS null function packet");
	return _sta_interface.radiotap / Dot11(addr1=_dst_interface.mac_address , addr2=_sta_interface.mac_address, addr3=_dst_interface.mac_address,type=2,subtype=4,FCfield=_FCField);

def send_qos_null_function_packet(_src_interface, _dst_interface, _FCField=0x01):
	logger.info("send a Null function (nodata) packet");
	packet = generate_qos_null_function_packet(_src_interface,_dst_interface, _FCField);
	_src_interface.send_packet(packet);

class Qos_Null_Function():
		

	def __init__(self,STA,AP):
		self.STA = STA;
		self.AP = AP;
	
	def send_Null_Func(self,_FCField=0x01):
		logger.info("Null Function (nodata) packet will send");

		sendp(packet,iface=self.STA.ifc_name,verbose=0)
		logger.info("Null function (nodata) packet was sent");


            
if __name__ == "__main__":
	print("\n\n")
	print("")

	
	STA = STA_Interface(ifc_name="wlx9cc9eb21fa6e",ifc_mac="9c:c9:eb:21:fa:6e");
	AP = AP_Interface(bssid="18:ec:e7:5f:a2:04",essid = "Buffalo-A-A200-Open")

	s = Qos_Null_Function(STA,AP);
	s.send_Null_Func();




