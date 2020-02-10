import struct

def u_ethernet(packet):
    return struct.unpack('! 6s 6s H', packet)

def u_ip(packet):
    return struct.unpack('!B B H H H B B H 4s 4s', packet)

def u_tcp(packet):
    return struct.unpack('!H H 2H 2H H H H H', packet)

def u_udp(packet):
	return struct.unpack('!H H H H', packet)

def u_arp(packet):
	return struct.unpack('!H H B B H 6s 4s 6s 4s', packet)

def u_dns(packet):
	return struct.unpack('!H H H H H H', packet)

def u_domain(domain):
	res = ""
	tmpidx = 0
	idx = 0
	while True:
		if domain[idx] is 0:
			break
		else:
			tmpidx = idx
			idx += domain[idx] + 1
			for i in range(tmpidx+1, idx):
				res += chr(domain[i])
			res += "."
	return res[:-1]

def u_radiotap(packet):
	return struct.unpack('!B B H Q B B H H H H H', packet)