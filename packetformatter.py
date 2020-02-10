def mac2str(mac):
    return ':'.join(map('{:02X}'.format, mac))

def ip2str(ip):
    return '.'.join(map('{:d}'.format, ip))