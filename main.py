import scapy.all as scapy
import json
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

#! Treba spravit extr subor pre L2 a L1 a nacitanie do Dict dole

ETHER_TYPES = {}
SAPS = {}
IP_PROTOCOLS = {}
IEEE_PID = {}
try:
    with open('./constants.txt', 'r') as f:
        data_list = json.load(f)
        
        ETHER_TYPES = data_list[0]
        SAPS = data_list[1]
        IP_PROTOCOLS = data_list[2]
        IEEE_PID = data_list[3]
        f.close()
except FileNotFoundError:
    print("File was not found")
    
print(ETHER_TYPES)

def analyze_eth_packet(number, pckt):
    eth_packet = {
            'frame_number': number,
            'len_frame_pcap': '',
            'len_frame_medium': '',
            'frame_type': '',
            'src_mac': '',
            'dst_mac': '',
        }



    for pc in pckt:
        eth_packet['len_frame_pcap'] = len(pc)
        eth_packet['len_frame_medium'] = len(pc) + 4
        is_IEEE_type = int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16) <= 1563
        
        if not is_IEEE_type: # Check if ETHERNET II or Not
            
            eth_packet['frame_type'] = 'ETHERNET II'
            eth_packet['src_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[6:12]).upper()
            eth_packet['dst_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[:6]).upper()
            # eth_packet['src_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[26:30])
            # eth_packet['dst_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[30:34])
            # if ETHER_TYPES.get(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16), "Unknown") != "Unknown":
            #     eth_packet['ether_type'] = ETHER_TYPES.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16)))
            #     eth_packet['protocol'] = IP_PROTOCOLS.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[23:24]), 16)))
            #eth_packet['src_port'] = int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[34:36]), 16)
            #eth_packet['dst_port'] = int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[36:38]), 16)
            eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
        
        else: # If not Eth II then check for Novell and IEEE
            
            has_Snap = ''.join(f'{byte:02x}' for byte in pc.__bytes__()[14:16]) == 'aaaa'
            is_Novell = ''.join(f'{byte:02x}' for byte in pc.__bytes__()[14:16]) == 'ffff'
            if is_Novell:
                eth_packet['frame_type'] = 'IEEE 802.3 RAW'
                eth_packet['src_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[6:12]).upper()
                eth_packet['dst_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[:6]).upper()
                # eth_packet['src_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[26:30])
                # eth_packet['dst_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[30:34])             
                eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
                    
            else: # If not IEE RAW then check for LLC or LLC + SNAP
                
                if has_Snap:
                    eth_packet['frame_type'] = 'IEEE 802.3 LLC & SNAP'
                    eth_packet['src_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[6:12]).upper()
                    eth_packet['dst_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[:6]).upper()
                    # eth_packet['src_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[26:30])
                    # eth_packet['dst_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[30:34])
                    if IEEE_PID.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[20:22]), 16)), "Unknown") != "Unknown":
                        eth_packet['pid'] = IEEE_PID.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[20:22]), 16)))
                        # print(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[20:22]), 16))
                    eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
                else:
                    eth_packet['frame_type'] = 'IEEE 802.3 LLC'
                    eth_packet['src_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[6:12]).upper()
                    eth_packet['dst_mac'] = ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[:6]).upper()
                    # eth_packet['src_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[26:30])
                    # eth_packet['dst_ip'] = '.'.join(str(byte) for byte in pc.__bytes__()[30:34])
                    eth_packet['sap'] = SAPS.get(int(pc.__bytes__()[15]), 16)
                    eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
        
        return eth_packet

def analyze_pcap(data):
    """function for analyzing each packet from the pcap file

    Args:
        data (.pcap): tcp/dump in .pcap format

    Returns:
        list: list of all captured and formated frames
    """
    datapcap = scapy.rdpcap(data)
    frame_number = 1
    frames = []
    for pc in datapcap:
        frames.append(analyze_eth_packet(frame_number, pc))
        frame_number += 1
    
    return frames

def format_for_yaml(hex_string):
    """Function for formatting the HEX FRAME for YAML

    Args:
        hex_string (str): hex data in string format for easier formatting

    Returns:
        list: List of Parsed hex to 16 bytes 
    """
    formatted_hex_dump = []
    for i in range(0, len(hex_string)):
        if i > 0 and i % 32 == 0:
            formatted_hex_dump.append("\n")

        formatted_hex_dump.append(hex_string[i])

        if i != len(hex_string) - 1 and i % 32 != 31 and i % 2 == 1:
            formatted_hex_dump.append(" ")
    formatted_hex_dump.append("\n")
    formatted_hex_dump = LiteralScalarString("".join(formatted_hex_dump).upper())
    return formatted_hex_dump

if __name__ == '__main__':
    print("STARTING")
    filename = './Vzor/test_pcap_files/vzorky_pcap_na_analyzu/trace-27.pcap'
    # filename = './data.pcap'
    pcap_data = analyze_pcap(filename)
    
    yaml = YAML()
    with open('output.yaml', 'w') as f:
        
        yaml.dump(
            {"name":'PKS2023/24',
             "pcap_name": filename ,
             "packets": pcap_data }
            , f)
    f.close()
    print('DONE')