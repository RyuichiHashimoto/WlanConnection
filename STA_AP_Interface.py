from scapy.all import *
from time import sleep
from util.WlanLogger  import logger;
from concurrent import futures
import random

#from protocol.Acknowledgement import sendAckPacket;
from protocol.Deauthentication import send_deauth_packet
from protocol.Disassociation import send_disassoc_packet
from protocol.NullFunction import send_qos_null_function_packet
from protocol.Beacon import scan_beacon_packet;
from protocol.Probe import send_probe_request_packet, probe_resq_resp_process;
from protocol.DHCP import DHCP_cliend_process;
from protocol.Authentication import send_authentication,authentication_process
from protocol.Association import association_process
from protocol.ARP import arp_sender_process,arp_response_process
from protocol.ICMP import icmp_sender_process
from protocol.ElementTag import extract_tagged_parameter_from_dot11elt
from protocol.EAPOL import four_way_hand_shake



class Interface:

	def __init__(self,mac_address = None,ip_address="0.0.0.0"):
		self.mac_address = mac_address;
		self.IP_address = ip_address;

class STA_Interface(Interface):

	WAIT_TIME_INTERVAL =0.2;

	def __init__(self,_ifc_name,_mac_addr,ip_address="0.0.0.0"):
		"""	      
		:param ifc_name: WLAN interface to use as a monitor
        :param channel: Channel to operate on
	    :param sta_mac: MAC address of the STA
		"""	
		logger.debug("generate a STA_Interface object ...")

		## layer1 (physical layer) information
		self.__generate_radiotap_header();
		self.dot11_rates = Dot11EltRates();

		## layer2 (data link layer) information
		self.ifc_name = _ifc_name;
		self.mac_address = _mac_addr;
		
		## layer3 (ip layer) information; 
		self.IP_address = ip_address;
		self.subnet_mask = "255.255.255.255";
		self.lease_time = 0;
		self.router = "0.0.0.0";
		self.dns_server = "0.0.0.0";

		logger.debug("a STA Interface object was generated.");

	def send_packet(self,packet, waitedTime = 0.1):
		sleep(waitedTime);
		packet[Dot11].SC = random.randint(0, 1000) << 4;
		sendp(packet, iface=self.ifc_name, verbose=0);

	def recv_packet(self, filter, timeout=5):
		return sniff(iface=self.ifc_name, lfilter= filter,stop_filter=filter, timeout=timeout);

	def is_packet_for_me(self,packet):
		seen_receiver = packet[Dot11].addr1;
		return (seen_receiver == "ff:ff:ff:ff:ff:ff" or  seen_receiver == self.mac_address)

	def __generate_radiotap_header(self):
		logger.debug("generate a radiotap header beforehand.");
		self.radiotap = RadioTap(present='Rate+Channel+Antenna+dBm_AntSignal')
		self.radiotap.ChannelFrequency = 5220;
		self.radiotap.ChannelFlags = 320;
		self.radiotap.Rate = 0;
		self.radiotap.dBm_AntSignal = -30;
		self.radiotap.Antenna = 0;

class AP_Interface(Interface):

	def __init__(self,bssid,essid,ip_address = "0.0.0.0",password="12345678"):
		logger.debug("generate an AP interface.");
		super().__init__(mac_address = bssid,ip_address = ip_address);
		self.bssid = bssid;
		self.essid = essid;
		self.password = password;

	## this packet assumes that packet has a 802.11 Data layer.
	def is_packet_transmitted_by_me(self,packet):
		return packet[Dot11].addr2 == self.bssid;

class Dot11EltRates(Packet):
	"""
	Our own definition for the supported rates field.
	"""
	supported_rates = [0x0c,0x12,0x18,0x24,0x30, 0x48, 0x60, 0x6c];

	fields_desc = [ByteField("ID",1),ByteField("Len",len(supported_rates))];

	for index,rate in enumerate(supported_rates):
		fields_desc.append(ByteField("supported_rate{0}".format(index+1),rate));

def connect_to_open():
	ifc_name = "wlx9cc9eb21fa6e";
	ifc_mac = "9c:c9:eb:21:fa:6e"
	STA = STA_Interface(ifc_name, ifc_mac);
	# AP = AP_Interface(bssid="18:ec:e7:5f:a2:04",essid = "Buffalo-A-A200-Open");
	AP = AP_Interface(bssid="18:ec:e7:5f:a2:00", essid="Buffalo-G-A200-wpa2");
	# send_deauth_packet(STA,AP,reason=3);
	# send_disassoc_packet(STA,AP,reason=7);
	# send_qos_null_function_packet(STA,AP);
	"""
    beacon_packet = scan_beacon_packet(STA,AP);
    essid_tag = Dot11Elt(ID='SSID', info=AP.essid);
    rates_tag = Dot11Elt(ID='Rates', info=STA.dot11_rates);
    dsset_tag = Dot11Elt(ID='DSset', info='\x2c');
    tagged_param = essid_tag / rates_tag / dsset_tag;
    probe_resq_resp_process(STA,AP,tagged_param);
    """
	authentication_process(STA, AP);
	logger.info("------------------------------------")
	association_process(STA, AP)
	logger.info("------------------------------------")
	dis, off, req, ack = DHCP_cliend_process(STA, AP)
	# logger.info("------------------------------------");
	server_ipaddr = [option[1] for option in req[DHCP].options if option[0] == "server_id"][0];
	AP_Interface = Interface(ip_address=server_ipaddr);
	# logger.info("------------------------------------")
	responce_packet = arp_sender_process(STA, AP, AP_Interface);
	AP_Interface.mac_address = responce_packet[ARP].hwsrc
	logger.info("------------------------------------")
	icmp_sender_process(STA=STA, AP=AP, Target_Interface=AP_Interface);


if __name__ == "__main__":
	ifc_name = "wlx9cc9eb21fa6e";
	ifc_mac = "9c:c9:eb:21:fa:6e"
	logger.info("")
	logger.info("----------------------------------")
	logger.info("          pseudo STA TOOL         ")
	logger.info("----------------------------------")
	STA = STA_Interface(ifc_name,ifc_mac);
	AP = AP_Interface(bssid="18:ec:e7:5f:a2:00", essid="Buffalo-G-A200-wpa2");
	beacon_packet = scan_beacon_packet(STA,AP);
	TagList = extract_tagged_parameter_from_dot11elt(beacon_packet[Dot11Elt]);

	rsn_Tag = [ o for o in TagList if o.ID == 48][0]
	essid_tag = Dot11Elt(ID='SSID', info=AP.essid);
	rates_tag = Dot11Elt(ID='Rates', info=STA.dot11_rates);
	dsset_tag = Dot11Elt(ID='DSset', info='\x2c');

	tagged_param = essid_tag / rates_tag / dsset_tag/rsn_Tag;
	#probe_resq_resp_process(STA, AP, tagged_param);
	#send_deauth_packet(STA,AP)
	authentication_process(STA, AP);

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=1);
	## recieve process (worker 1)
	recv_thread = executor.submit(four_way_hand_shake, STA, AP,rsn_Tag);
	association_process(STA, AP,tagged_param);
	recv_thread.result();











