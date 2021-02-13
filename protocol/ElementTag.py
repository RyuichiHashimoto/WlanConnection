from scapy.all import *
from copy import deepcopy


TAGNUMBER_RSNInfo=48


def extract_tagged_parameter_from_dot11elt(TaggedParameter:Dot11Elt):
    retList = [];
    pkt_elt = deepcopy(TaggedParameter);

    while isinstance(pkt_elt, Dot11Elt):
        next_plt_packet = pkt_elt.payload;
        pkt_elt.remove_payload()
        retList.append(pkt_elt)
        pkt_elt = next_plt_packet;

    return retList;