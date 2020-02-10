import pcap
import time
import color
from packetpacker import *
from packetformatter import *

eth_type_dict = {
    0x0800 : 'IPv4',
    0x0806 : 'ARP', 
    0x8035 : 'RARP',
    0X86DD : 'IPv6'
}

ip_proto_dict = {
    0x01 : 'ICMP',
    0X02 : 'IGMP',
    0X03 : 'GGP',
    0x06 : 'TCP',
    0x11 : 'UDP'
}

def dump(packet):
    print()
    for i in range(len(packet)):
        print(" %02X" % packet[i], end="")
        if i % 16 is 15:
            print()
    print()

def sniff(network_interface):
    sniffer = pcap.pcap(name=network_interface, promisc=True, immediate=True, timeout_ms=50)

    for ts, pkt in sniffer:
        tmp = ""
        result = color.bold
        result += time.strftime('%y-%m-%d %H:%M:%S',time.localtime(time.time()))
        #result += str(time.time())
        result += color.end
        #dump(pkt)
        vision, pad, hlen, pflag, flags, data_rate, channel, cflag, signal, rxflag, signal2 = u_radiotap(pkt[:24])
        result += " PWR : "
        result += str(-(((signal>>8)^0xFF)+1))







        """
        dst_mac, src_mac, eth_type = u_ethernet(pkt[:14]) 
        result += " "
        result += mac2str(src_mac)
        result += " -> "
        result += mac2str(dst_mac)
        try:
            if eth_type_dict[eth_type] is 'IPv4':            
                vhl, tos, tlen, identification, ff, ttl, proto, cs, src_ip, dst_ip = u_ip(pkt[14:34])                        
                result += "  "
                result += ip2str(src_ip)
                result += " -> "
                result += ip2str(dst_ip)
                result += " "*(30-(len(ip2str(src_ip))+len(ip2str(dst_ip))))

                try:
                    if ip_proto_dict[proto] is 'TCP':
                        src_port, dst_port, *sth = u_tcp(pkt[34:54])
                        if src_port is 80 or dst_port is 80:
                            result += color.green
                            result += "[HTTP]  "
                            result += str(src_port)
                            result += " -> "
                            result += str(dst_port)
                        elif src_port is 443 or dst_port is 443:
                            result += color.green
                            result += "[HTTPS] "
                            result += str(src_port)
                            result += " -> "
                            result += str(dst_port)
                        else:
                            result += color.purple
                            result += "[TCP]   "
                            result += str(src_port)
                            result += " -> "
                            result += str(dst_port)
                    elif ip_proto_dict[proto] is 'UDP':
                        src_port, dst_port, *sth = u_udp(pkt[34:42])
                        if src_port is 53 or dst_port is 53:
                            t_id, flags, questions, ansRRs, authRRs, addRRs = u_dns(pkt[42:54])
                            res = flags >> 15
                            domain = u_domain(pkt[54:])

                            if res is 0:
                                result += color.back_blue
                                result += "[DNS] "
                                result += "Standard query "
                                result += str(hex(t_id))
                                result += " "
                                result += domain

                            elif res is 1:
                                result += color.back_blue
                                result += "[DNS] "
                                result += "Standard query response "
                                result += str(hex(t_id))
                                result += " "
                                result += str(domain)

                        else:
                            result += color.blue
                            result += "[UDP]   "
                            result += str(src_port)
                            result += " -> "
                            result += str(dst_port)
                            result += " Len="
                            result += str(len(pkt[54:]))
                except KeyError:
                    result += color.red
                    result += "Unknown Packet"
                    result += color.end
                    
            elif eth_type_dict[eth_type] is 'ARP':
                '''
                result += "  "
                result += mac2str(src_mac)
                result += " -> "
                result += mac2str(dst_mac)
                '''
                result += color.yellow
                result += " "*36
                result += "[ARP] "
                hd_type, proto_type, hd_len, proto_len, opcode, sha, spa, tha, tpa = u_arp(pkt[14:42])
                if opcode is 1:
                    result += " Who has "
                    result += ip2str(tpa)
                    result += "? Tell "
                    result += mac2str(sha)
                elif opcode is 2:
                    result += " "
                    result += ip2str(spa)
                    result += " is at "
                    result += mac2str(sha)
        except KeyError:
            result += color.red
            result += "Unknown Packet"
            result += color.end
        result += color.end
        print(result)
        """
        print(result)
    
