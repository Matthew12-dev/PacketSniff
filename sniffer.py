import socket, struct
# import argparse
# import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destino: {dest_mac}, Origen: {src_mac}, Protocol: {eth_proto}')

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

def get_mac_address(bytes_addr):
    bytes_str = map('{0.2x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

main()
