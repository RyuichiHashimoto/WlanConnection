from scapy.all import *
from concurrent import futures
from util.WlanLogger import logger

ICMP_TYPE_REQUEST = 8;
ICMP_TYPE_RESPONSE = 0;

OP_MASSAGE_HASH = {ICMP_TYPE_RESPONSE:"request",ICMP_TYPE_RESPONSE:"response"}

def icmp_sender_process(STA,AP, Target_Interface):
	logger.info("ICMP sender process (to "+ Target_Interface.IP_address+")");

	## generate a ICMP request packet.
	icmp_packet = generate_icmp_request(STA,AP,Target_Interface);

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_icmp_response_packet, STA, Target_Interface,AP);

	## sender process (worker 2)
	logger.info("send an ICMP request packet.");
	send_thread = executor.submit(STA.send_packet, icmp_packet);

	## synchronization
	a = send_thread.result();
	response_packet = recv_thread.result();

	if (response_packet):
		logger.info("ICMP sender process (to "+ Target_Interface.IP_address+") has finished successsfully");
		return response_packet;
	else:
		logger.error("ICMP sender process (to " + Target_Interface.IP_address + ") has failed.");


def recv_icmp_response_packet(src,dst, AP):
	logger.info("wait until I capture an arp request packet from " + dst.mac_address);
	packets = src.recv_packet(filter=lambda x: ((x.haslayer(ICMP)) and (x[ICMP].type == ICMP_TYPE_RESPONSE) and (x[Dot11].addr3 == dst.mac_address) and  (AP.is_packet_transmitted_by_me(x)) and (src.is_packet_for_me(x))));

	if(len(packets) == 0):
		logger.error("cannot capture an arp request from " + AP.bssid + " (" + AP.essid + ") .");
		return;

	return packets[0];

def generate_icmp_request(STA, AP, target):
	logger.debug("generate an icmp request packet to " + target.IP_address + " (" +target.mac_address+")");

	## layer 1
	Radiotap = STA.radiotap

	## layer 2 (802.11)
	Dot11_Header = Dot11(addr1=AP.bssid, addr2=STA.mac_address, addr3=target.mac_address, FCfield=0x01, subtype=8,type=2) / Dot11QoS();

	llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
	snap_header = SNAP(OUI=0x000000, code=0x0800)

	## layer 3 (IP);
	IP_header = IP(src=STA.IP_address, dst=target.IP_address );

	## layer 4 (ICMP)
	icmp_header = ICMP();

	return Radiotap / Dot11_Header / llc_header / snap_header / IP_header / icmp_header

def generate_icmp_response_packet(src,AP,icmp_request_packet):
	logger.debug("generate an ICMP response packet");

	## layer 1
	Radiotap = src.radiotap

	## layer 2 (802.11)
	Dot11_Header = Dot11(addr1=AP.bssid, addr2=src.mac_address, addr3=icmp_request_packet[Dot11].addr3, FCfield=0x01, subtype=8,
						 type=2) / Dot11QoS();
	llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
	snap_header = SNAP(OUI=0x000000, code=0x0800)

	## layer 3 (IP);
	IP_header = IP(src=src.IP_address, dst=icmp_request_packet[IP].src);

	## layer 4 (ICMP)
	icmp_header = icmp_request_packet[ICMP].copy();
	icmp_header.type = ICMP_TYPE_RESPONSE;
	del icmp_header.chksum ## for recaluclation a checksum value of ICMP header

	return Radiotap/Dot11_Header/llc_header/snap_header/IP_header/icmp_header;
