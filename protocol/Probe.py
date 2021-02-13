from scapy.all import *
from util.WlanLogger import logger
from concurrent import futures

def generate_probe_request_packet(_sta_interface,_dst_interface, tagged_param):
	logger.info("generate a probe request packet packet");
	return _sta_interface.radiotap / Dot11(addr1=_dst_interface.mac_address , addr2=_sta_interface.mac_address, addr3=_dst_interface.mac_address,type=0,subtype=4)/Dot11ProbeReq()/tagged_param;

def probe_resq_resp_process(_src_interface, _dst_interface, tagged_param):
	logger.info("probe request/response process will start");

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## sender process (worker 2)
	send_thread = executor.submit(send_probe_request_packet, _src_interface, _dst_interface, tagged_param);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_probe_response_packet, _src_interface, _dst_interface);

	send_thread.result();
	response_packet = recv_thread.result();

	logger.info("Probe request/response process successfully finished");
	return response_packet


def send_probe_request_packet(_src_interface, _dst_interface, tagged_param):
	packet = generate_probe_request_packet(_src_interface,_dst_interface,tagged_param);
	_src_interface.send_packet(packet);
	logger.info("send a probe request (SSID = " + _dst_interface.essid + ") packet");

def recv_probe_response_packet(_src_interface, _dst_interface):
	logger.info("wait until I capture a probe response packet from " + _dst_interface.bssid + " (" + _dst_interface.essid + ") ...");

	packets = _src_interface.recv_packet(filter=lambda x: (  (x.haslayer(Dot11ProbeResp)) and (x[Dot11].addr2 == _dst_interface.bssid) and (_src_interface.is_packet_for_me(x))));

	if(len(packets) == 0):
		logger.error("cannot capture a probe response  packet from " + _dst_interface.bssid + " (" + _dst_interface.essid + ") ...");
		raise Exception("cannot capture a probe response  packet from " + _dst_interface.bssid + " (" + _dst_interface.essid + ") ...");

	return packets[0];