from scapy.all import *
from util.WlanLogger import logger

def scan_beacon_packet(STA,AP):
	logger.info("Beacon scan process will start");
	logger.info("please wait until a beacon packet is scanned from " + AP.bssid + " (" + AP.essid + ") ...");

	packets = STA.recv_packet(filter=lambda x: (  (x.haslayer(Dot11Beacon)) and (x[Dot11].addr2 == AP.bssid) and (STA.is_packet_for_me(x))));

	if(len(packets) == 0):
		logger.error("cannot scan a beacon packet from " + AP.bssid + " (" + AP.essid + ") ...");
		raise Exception("cannot scan a beacon packet from " + AP.bssid + " (" + AP.essid + ") ...");

	logger.info("Beacon scan process has finished");
	return packets[0];