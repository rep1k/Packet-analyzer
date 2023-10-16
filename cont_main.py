import scapy.all as scapy
import json
import sys
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString


#? DICT for CONSTANTS
ETHER_TYPES = {}
SAPS = {}
IP_PROTOCOLS = {}
IEEE_PID = {}
PORTS = {}
COMMS = {}
ICMP_TYPES = {}

try:
    with open('./constants.txt', 'r') as f:
        data_list = json.load(f)
        
        ETHER_TYPES = data_list[0]
        SAPS = data_list[1]
        IP_PROTOCOLS = data_list[2]
        IEEE_PID = data_list[3]
        PORTS = data_list[4]
        COMMS = data_list[5]
        ICMP_TYPES = data_list[6]
        f.close()
except FileNotFoundError:
    print("File was not found")


def get_src_ip(pc):
    return '.'.join(str(byte) for byte in pc.__bytes__()[26:30])

def get_arp_src_ip(pc):
    return '.'.join(str(byte) for byte in pc.__bytes__()[28:32])


def get_dst_ip(pc):
    return '.'.join(str(byte) for byte in pc.__bytes__()[30:34])

def get_arp_dst_ip(pc):
    return '.'.join(str(byte) for byte in pc.__bytes__()[38:42])

def get_src_port(pc):
    return int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[34:36]), 16)

def get_dst_port(pc):
    return int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[36:38]), 16)

def get_src_mac(pc):
    return ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[6:12]).upper()

def get_dst_mac(pc):
    return ':'.join(f'{byte:02x}' for byte in pc.__bytes__()[:6]).upper()

def get_arp_code(pc):
    return "REQUEST" if int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[21:22]), 16) == 1 else "REPLY"

def get_ether_type(pc):
    return ETHER_TYPES.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16)))

def get_tcpip_protocol(pc):
    return IP_PROTOCOLS.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[23:24]), 16)))

def get_application_protocol_by_src(pc):
    return PORTS.get(str(get_src_port(pc)))

def get_application_protocol_by_dst(pc):
    return PORTS.get(str(get_dst_port(pc)))

def get_pid(pc):
    return IEEE_PID.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[20:22]), 16)), "Unknown")

def get_sap(pc):
    # print(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[15:16]),16)))
    return SAPS.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[15:16]),16)))

def get_flags(pc):
    return COMMS.get(str(int(str(''.join(f'{byte:02x}' for byte in pc.__bytes__()[47:48])), 16)))
    # return int(str(pc.__bytes__().hex()[48]), 16)

def get_comm_sequence(pc):
    return int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[38:42]), 16)

def analyze_eth_packet(number, pckt, filter_flag):
    """_summary_

    Args:
        number (int): integer to map frame number
        pckt (packet): packet

    Returns:
        dict: returns formatted dictionary
    """

    eth_packet = {
            'frame_number': number,
            'len_frame_pcap': '',
            'len_frame_medium': '',
            'frame_type': '',
            'src_mac': '',
            'dst_mac': '',
            # 'ether_type':'',
        }
    
    comms = []

    for pc in pckt:
        eth_packet['len_frame_pcap'] = len(pc)
        eth_packet['len_frame_medium'] = len(pc) + 4
        is_IEEE_type = int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16) <= 1563
        
        
        if not is_IEEE_type: #? Check if ETHERNET II or Not
            
            eth_packet['frame_type'] = 'ETHERNET II'
            eth_packet['src_mac'] = get_src_mac(pc)
            eth_packet['dst_mac'] = get_dst_mac(pc)
            if ETHER_TYPES.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16)), "Unknown") != "Unknown":
                eth_packet['ether_type'] = get_ether_type(pc)
                
                # TODO: CHECK FOR IPV6 LOG
        
            
            #! ARP SECTION 
            if ETHER_TYPES.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[12:14]), 16))) == "ARP":
                # print("ARP SECTION")
                eth_packet['arp_opcode'] = get_arp_code(pc)
                eth_packet['src_ip'] = get_arp_src_ip(pc)
                eth_packet['dst_ip'] = get_arp_dst_ip(pc)
            else:
                eth_packet['src_ip'] = get_src_ip(pc)
                eth_packet['dst_ip'] = get_dst_ip(pc)
                eth_packet['protocol'] = get_tcpip_protocol(pc)
                eth_packet['src_port'] = get_src_port(pc)
                eth_packet['dst_port'] = get_dst_port(pc)
            
            
                # !TCP / UDP SECTION
                if eth_packet['protocol'] == "TCP" or eth_packet['protocol'] == "UDP":
                    if PORTS.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[34:36]), 16)), "Unknown") == "Unknown":
                        eth_packet['app_protocol'] = get_application_protocol_by_dst(pc)
                    else:
                        eth_packet['app_protocol'] = get_application_protocol_by_src(pc)
                    if eth_packet['protocol'] == 'TCP' and filter_flag:
                        eth_packet['flags'] = get_flags(pc)
                    elif eth_packet['protocol'] == 'UDP' and filter_flag:
                        pass
                        
                if eth_packet['protocol'] == "ICMP":

                    eth_packet['icmp_type'] = ICMP_TYPES.get(str(int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[34:35]), 16)))
                    eth_packet['icmp_id'] = int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[18:20]), 16)
                    eth_packet['icmp_seq'] = int(''.join(f'{byte:02x}' for byte in pc.__bytes__()[40:42]), 16)

                    del eth_packet['dst_port'], eth_packet['src_port']
            eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
        
        else: #? If not Eth II then check for Novell and IEEE
            
            has_Snap = ''.join(f'{byte:02x}' for byte in pc.__bytes__()[14:16]) == 'aaaa'
            is_Novell = ''.join(f'{byte:02x}' for byte in pc.__bytes__()[14:16]) == 'ffff'
            
            
            if is_Novell:
                eth_packet['frame_type'] = 'IEEE 802.3 RAW'
                eth_packet['src_mac'] = get_src_mac(pc)
                eth_packet['dst_mac'] = get_dst_mac(pc)
          
                eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
                    
            else: # ?If not IEE RAW then check for LLC or LLC + SNAP
                
                if has_Snap:
                    eth_packet['frame_type'] = 'IEEE 802.3 LLC & SNAP'
                    eth_packet['src_mac'] = get_src_mac(pc)
                    eth_packet['dst_mac'] = get_dst_mac(pc)
                    
                
                    if get_pid(pc) != "Unknown":
                        eth_packet['pid'] = get_pid(pc)
                    eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
                
                
                else:
                    eth_packet['frame_type'] = 'IEEE 802.3 LLC'
                    eth_packet['src_mac'] = get_src_mac(pc)
                    eth_packet['dst_mac'] = get_dst_mac(pc)
                    eth_packet['sap'] = get_sap(pc)
                    eth_packet['hexa_frame'] = format_for_yaml(str(pc.__bytes__().hex()))
                    
        return eth_packet

def analyze_pcap(data, filter_flag):
    """function for analyzing each packet from the pcap file

    Args:
        data (.pcap): tcp/dump in .pcap format

    Returns:
        list: list of all captured and formated frames
    """
    datapcap = scapy.rdpcap(data)
    # print(datapcap)
    frame_number = 1
    frames = []
    for pc in datapcap:
        # print(pc)
        frames.append(analyze_eth_packet(frame_number, pc, filter_flag))
        frame_number += 1
    
    return frames

def filter_switch(frames ,arg):
    
    # print(frames)
    filtered_frames = []
    
    for frame in frames:
        try:
            if frame['frame_type'] == "ETHERNET II" and frame['protocol'] == "TCP":
                if arg in frame['app_protocol']:
                    filtered_frames.append(frame)
        except TypeError:
            print("None")
            continue
        except KeyError:
            continue
        try:
            if frame['frame_type'] == "ETHERNET II" and frame['protocol'] == "UDP":

                if arg in frame['app_protocol']:
                    filtered_frames.append(frame)
        except TypeError:
            continue
    
    return filtered_frames


def track_connections(frames):
    ongoing_connections = {}  # Key: (src_ip, src_port, dst_ip, dst_port), Value: List of associated frames
    completed_connections = []
    reset_connections = []
    
    for frame in frames:
        src_ip, src_port = frame['src_ip'], frame['src_port']
        dst_ip, dst_port = frame['dst_ip'], frame['dst_port']
        
        # Use frozenset to make the key order-agnostic
        connection_key = frozenset(((src_ip, src_port), (dst_ip, dst_port)))

        # If the flag is 'SYN' (or 'SYN-ACK' for bidirectional SYN) and this connection doesn't exist, initialize it
        if frame['flags'] in ['SYN', 'SYN-ACK'] and connection_key not in ongoing_connections:
            ongoing_connections[connection_key] = []
        
        # If this is a frame for an existing connection, append it
        if connection_key in ongoing_connections:
            ongoing_connections[connection_key].append(frame)
        
        # If the flag is 'RST' or 'FIN-ACK', check if it concludes the connection
        if frame['flags'] == 'RST':
            if connection_key in ongoing_connections:
                reset_connections.append(ongoing_connections.pop(connection_key))
        elif frame['flags'] == 'FIN-ACK':
            if connection_key in ongoing_connections:
                completed_connections.append(ongoing_connections.pop(connection_key))
    
    # At the end, all remaining connections in ongoing_connections can be considered as incomplete/ongoing
    incomplete_connections = list(ongoing_connections.values())

   
    return {
        "completed": completed_connections,
        "reset": reset_connections,
        "incomplete": incomplete_connections
    }


# def get_connection_key(frame: Dict) -> str:
#     src = (frame['src_ip'], frame.get('src_port'))
#     dst = (frame['dst_ip'], frame.get('dst_port'))
#     # Convert tuples to strings and sort to ensure consistency
#     key_parts = sorted([str(src), str(dst)])
#     return '|'.join(key_parts)

# def filter_tftp_communication(data):
#     ongoing_tftp_connections = set()
#     tftp_communications = {}

#     for frame in data:
#         connection_key = get_connection_key(frame)

#         # If the frame is an initialization or belongs to an ongoing communication, process it
#         if frame.get('app_protocol') == 'TFTP' or connection_key in ongoing_tftp_connections:
#             if connection_key not in tftp_communications:
#                 tftp_communications[connection_key] = []

#             tftp_communications[connection_key].append(frame)

#             # If it's an initialization, mark this communication as ongoing
#             if frame.get('app_protocol') == 'TFTP':
#                 ongoing_tftp_connections.add(connection_key)

#     # Collate results
#     result = list(tftp_communications.values())
#     return result

def filter_tftp_connection(frames):
    pass

def filter_icmp_connection(frames):
    filter_frames = []
    for frame in frames:
            
        # src_ip, src_port = frame['src_ip'], frame['src_port']
        # dst_ip, dst_port = frame['dst_ip'], frame['dst_port']
        
        # # Use frozenset to make the key order-agnostic
        # connection_key = frozenset(((src_ip, src_port), (dst_ip, dst_port)))
        try:
            if frame['frame_type'] == "ETHERNET II" and frame['protocol'] == "ICMP":
                
                filter_frames.append(frame)
        except KeyError:
            continue
    return filter_frames

def process_icmp_frames(frames):
    complete_comms = []
    partial_comms = []

    # To keep track of the processed frames
    processed_frames = set()

    for frame in frames:
        if frame["icmp_type"] == "ECHO REQUEST":
            # Check for ECHO REPLY
            reply_frame = next((f for f in frames if f["icmp_type"] == "ECHO REPLY" and f["src_ip"] == frame["dst_ip"] and f["dst_ip"] == frame["src_ip"] and f["frame_number"] not in processed_frames), None)

            # Check for Destination Unreachable
            dest_unreachable_frame = next((f for f in frames if f["icmp_type"] == "DESTINATION UNREACHABLE" and f["src_ip"] == frame["dst_ip"] and f["dst_ip"] == frame["src_ip"] and f["frame_number"] not in processed_frames), None)

            if reply_frame:
                complete_comms.append({
                    "number_comm": len(complete_comms) + 1,
                    'src_comm': frame['src_ip'],
                    "dst_comm": frame['dst_ip'],
                    "packets": [frame, reply_frame]
                })
                processed_frames.add(frame["frame_number"])
                processed_frames.add(reply_frame["frame_number"])
            elif dest_unreachable_frame:
                complete_comms.append({
                    "number_comm": len(complete_comms) + 1,
                    'src_comm': frame['src_ip'],
                    "dst_comm": frame['dst_ip'],
                    "packets": [frame, dest_unreachable_frame]
                })
                processed_frames.add(frame["frame_number"])
                processed_frames.add(dest_unreachable_frame["frame_number"])
            else:
                partial_comms.append({
                    "number_comm": len(partial_comms) + 1,
                    'src_comm': frame['src_ip'],
                    "dst_comm": frame['dst_ip'],
                    "packets": [frame]
                })
                processed_frames.add(frame["frame_number"])

    # Any remaining ECHO REPLY or Destination Unreachable frames without a processed counterpart are partial
    for frame in frames:
        if frame["icmp_type"] in ["ECHO REPLY", "DESTINATION UNREACHABLE", "TIME EXCEEDED"] and frame["frame_number"] not in processed_frames:
            partial_comms.append({
                "number_comm": len(partial_comms) + 1,
                'src_comm': frame['src_ip'],
                "dst_comm": frame['dst_ip'],
                "packets": [frame]
            })
            processed_frames.add(frame["frame_number"])

    return {"complete_comms": complete_comms, "partial_comms": partial_comms}

def filter_arp_connection(frames):
    filter_frames = []
    
    
    for frame in frames:
            
        try:
            if frame['frame_type'] == "ETHERNET II" and frame['ether_type'] == "ARP":
                filter_frames.append(frame)
        except KeyError:
            continue
    return filter_frames

def process_arp_frames(frames):
    complete_comms = []
    partial_comms = []
    processed_frames = set()

    for frame in frames:
        if frame["frame_number"] not in processed_frames:
            if frame["arp_opcode"] == "REQUEST":
                # Look for a corresponding REPLY
                reply_frame = next(
                    (f for f in frames if f["arp_opcode"] == "REPLY" and
                     f["src_ip"] == frame["dst_ip"] and
                     f["dst_ip"] == frame["src_ip"]),
                    None
                )

                if reply_frame:
                    complete_comms.append({
                        "number_comm": len(complete_comms) + 1,
                        "packets": [frame, reply_frame]
                    })
                    processed_frames.add(frame["frame_number"])
                    processed_frames.add(reply_frame["frame_number"])
                else:
                    partial_comms.append({
                        "number_comm": len(partial_comms) + 1,
                        "packets": [frame]
                    })
                    processed_frames.add(frame["frame_number"])

            elif frame["arp_opcode"] == "REPLY":
                request_frame = next((f for f in frames if f["arp_opcode"] == "REQUEST" and
                     f["src_ip"] == frame["dst_ip"] and
                     f["dst_ip"] == frame["src_ip"]),
                    None
                )

                if not request_frame:
                    partial_comms.append({
                        "number_comm": len(partial_comms) + 1,
                        "packets": [frame]
                    })
                    processed_frames.add(frame["frame_number"])

    return {"complete_comms": complete_comms, "partial_comms": partial_comms}

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

def ip_statistic(frames):
    """Makes statistic of used source IPs and count the sent packets by them

    Args:
        frames (list): list of dictionaries containing the frames

    Returns:
        dict: dictionary of Ips and its sent packets
    """
    
    src_ips = []

    for frame in frames:
        try:
            if frame['ether_type'] != "IPv4": continue
            if 'src_ip' in frame.keys():
                src_ips.append(frame["src_ip"])
        except KeyError:
            continue
        
    uniques = set(src_ips)

    dict_ip = {}
    list_of_uniques = list(uniques)
    for n in range(0,len(uniques)):
        dict_ip.update({f'{list_of_uniques[n]}':f'{src_ips.count(list_of_uniques[n])}'})

    return dict_ip

def find_keys_with_max_values(d):
    """Finds the max sent packets from IPs

    Args:
        d (dict): dictionary of IPs and Values

    Returns:
        list: list of IP/s with the max sent packets
    """
    if not d:  #? check for empty dict
        return []


    max_val = max(d.values())
    
    keys_with_max_values = [key for key, value in d.items() if value == max_val]

    return keys_with_max_values


if __name__ == '__main__':
    print("STARTING")
    filename = './Vzor/test_pcap_files/vzorky_pcap_na_analyzu/eth-8.pcap'
    
    switch_flag = False
    argument = ""
    yaml = YAML()
    
    if '-p' in sys.argv:
        p_index = sys.argv.index('-p')
        try:
            arg_after_p = sys.argv[p_index + 1]
            if arg_after_p in PORTS.values():
                print(f"Argument after -p: {arg_after_p}")
                switch_flag = True
                argument = arg_after_p.upper()
            elif arg_after_p in ETHER_TYPES.values():
                print(f"Argument after -p: {arg_after_p}")
                switch_flag = True
                argument = arg_after_p.upper()
            elif arg_after_p in IP_PROTOCOLS.values():
                print(f"Argument after -p: {arg_after_p}")
                switch_flag = True
                argument = arg_after_p.upper()
            else:
                raise ValueError
        except ValueError:
            print("Nespravny filter")
            sys.exit(1)
        except IndexError:
            print("Error: -p option requires an argument")
            sys.exit(1)
    else:
        print("No filter used")
        
    pcap_data = analyze_pcap(filename, switch_flag)
    if switch_flag:
        if argument == "ARP":
            print("ARPPp")
            packets = filter_arp_connection(pcap_data)
            packets = process_arp_frames(packets)
            print("completed", packets['complete_comms'])
            print("Partial", packets['partial_comms'])
            with open("output_cont_2.yaml", "w") as fsf:
                    yaml.dump({
                        "name":'PKS2023/24',
                        "pcap_name": filename ,
                        "filter_name": argument,
                        "complete_comms": packets['complete_comms'],
                        "partial_comms": packets['partial_comms']
                    }, fsf)
        elif argument == "ICMP":
            packets = filter_icmp_connection(pcap_data)

            packets = process_icmp_frames(packets)
            with open("output_cont_2.yaml", "w") as fsf:
                    yaml.dump({
                        "name":'PKS2023/24',
                        "pcap_name": filename ,
                        "filter_name": argument,
                        "complete_comms":packets['complete_comms'],
                        "partial_comms": packets['partial_comms']
                    }, fsf)
        else:
            print(argument)
            pcap_data_filtered = filter_switch(pcap_data, argument)
            
            if pcap_data_filtered[0]['protocol'] == "TCP":
                # print("TCP")
                all_completed_coms = []
                all_incompleted_coms = []
                first_incomplete = []
                completed_coms = []
                incompleted_coms = []
                com_coms = {
                    'number_coms':0,
                    "src_comm": 0,
                    "dst_comm": 0,
                    "packets": completed_coms
                }
                incom_coms = {
                    'number_coms':0,
                    "src_comm": 0,
                    "dst_comm": 0,
                    "packets": completed_coms
                }


                pcap_data = track_connections(pcap_data_filtered)
                
                idx_incoms = 1
                
                for item_l in pcap_data['incomplete']:
                    incom_coms = {}
                    incompleted_coms = []

                    incom_coms['number_coms'] = idx_incoms
                    for i in item_l:
                        incom_coms['src_comm'] = i['src_ip']
                        incom_coms['dst_comm'] = i['dst_ip']
                        incompleted_coms.append(i)
                    incom_coms['packets'] = incompleted_coms[0]
                    idx_incoms += 1
                    all_incompleted_coms.append(incom_coms)
                try:
                    first_incomplete = all_incompleted_coms[0]
                except IndexError:
                    print("Prazdny incomplete list")        
                idx_comms = 1
                for item in pcap_data['completed']:
                    print(idx_comms)

                    # Initialize these inside the loop
                    com_coms = {}
                    completed_coms = []

                    com_coms['number_coms'] = idx_comms
                    for l in item:
                        com_coms['src_comm'] = l['src_ip']
                        com_coms['dst_comm'] = l['dst_ip']
                        completed_coms.append(l)
                    com_coms['packets'] = completed_coms
                    idx_comms += 1
                    all_completed_coms.append(com_coms)
            
                with open("output_cont_2.yaml", "w") as fsf:
                    yaml.dump({
                        "name":'PKS2023/24',
                        "pcap_name": filename ,
                        "filter_name": argument,
                        "complete_comms": all_completed_coms,
                        "partial_comms": first_incomplete,
                    }, fsf)
            elif pcap_data_filtered[0]['protocol'] == "UDP":
                print("UDP")

            
    else:
        stats = ip_statistic(pcap_data)
        ipv4_senders = [{'node': key, 'number_of_sent_packets': int(value)} for key, value in stats.items()]
        max_send_packets_by = find_keys_with_max_values(stats)
    
    
        with open('output_cont.yaml', 'w') as f:
            yaml.dump(
                {"name":'PKS2023/24',
                "pcap_name": filename ,
                "packets": pcap_data,
                "ipv4_senders":ipv4_senders,
                "max_send_packets_by":max_send_packets_by}
                , f)
        f.close()
    print('DONE')