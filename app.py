import csv
import scapy.all as scapy

# File to store captured packets
csv_file_path = 'C:\\Network Traffic Analyzer\\network.csv'

def process_packet(packet):
    output_text = ""
    if packet.haslayer(scapy.Ether):
        # Layer 2: Ethernet Frame Header
        src_mac = packet[scapy.Ether].src
        dst_mac = packet[scapy.Ether].dst
        ethertype = packet[scapy.Ether].type

        output_text += "\nEthernet Frame Header (Layer 2):"
        output_text += f"\nSource MAC Address: {src_mac}"
        output_text += f"\nDestination MAC Address: {dst_mac}"
        output_text += f"\nEtherType or Length: {ethertype}"

    if packet.haslayer(scapy.IP):
        # Layer 3: IP Header
        ip_header = packet[scapy.IP]
        version = ip_header.version
        ihl = ip_header.ihl
        tos = ip_header.tos
        total_length = ip_header.len
        identification = ip_header.id
        flags = ip_header.flags
        fragment_offset = ip_header.frag
        ttl = ip_header.ttl
        protocol = ip_header.proto
        checksum = ip_header.chksum
        src_ip = ip_header.src
        dst_ip = ip_header.dst
        options = ip_header.options

        output_text += "\n\nIP Header (Layer 3):"
        output_text += f"\nVersion: {version}"
        output_text += f"\nIHL (Internet Header Length): {ihl}"
        output_text += f"\nType of Service (ToS): {tos}"
        output_text += f"\nTotal Length: {total_length}"
        output_text += f"\nIdentification: {identification}"
        output_text += f"\nFlags: {flags}"
        output_text += f"\nFragment Offset: {fragment_offset}"
        output_text += f"\nTime to Live (TTL): {ttl}"
        output_text += f"\nProtocol: {protocol}"
        output_text += f"\nHeader Checksum: {checksum}"
        output_text += f"\nSource IP Address: {src_ip}"
        output_text += f"\nDestination IP Address: {dst_ip}"
        output_text += f"\nOptions: {options}"

    # ... (Repeat similar blocks for TCP, UDP, ICMP)

    # Payload
    payload = packet.payload
    output_text += "\n\nPayload:"
    output_text += f"\n{payload.show()}"

    # Print information to the console
    print(output_text)

    # Write information to the CSV file
    write_to_csv(src_mac, dst_mac, ethertype, version, ihl, tos, total_length, identification, flags, fragment_offset, ttl,
                 protocol, checksum, src_ip, dst_ip, options, str(payload))

def write_to_csv(src_mac, dst_mac, ethertype, version, ihl, tos, total_length, identification, flags, fragment_offset,
                 ttl, protocol, checksum, src_ip, dst_ip, options, payload):
    # Open the CSV file in append mode
    with open(csv_file_path, 'a', newline='') as csvfile:
        # Define the field names for the CSV
        fieldnames = ['Source MAC Address', 'Destination MAC Address', 'EtherType', 'Version', 'IHL',
                      'Type of Service (ToS)', 'Total Length', 'Identification', 'Flags', 'Fragment Offset',
                      'Time to Live (TTL)', 'Protocol', 'Header Checksum', 'Source IP Address', 'Destination IP Address',
                      'Options', 'Payload']

        # Create a CSV writer
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the information to the CSV file
        writer.writerow({'Source MAC Address': src_mac, 'Destination MAC Address': dst_mac,
                         'EtherType': ethertype, 'Version': version, 'IHL': ihl,
                         'Type of Service (ToS)': tos, 'Total Length': total_length,
                         'Identification': identification, 'Flags': flags,
                         'Fragment Offset': fragment_offset, 'Time to Live (TTL)': ttl,
                         'Protocol': protocol, 'Header Checksum': checksum,
                         'Source IP Address': src_ip, 'Destination IP Address': dst_ip,
                         'Options': options, 'Payload': payload})

# Use Scapy's sniff function to continuously capture live packets
# Customize the filter as needed (e.g., 'ip', 'tcp', 'udp', 'icmp')
def live_packet_capture():
    sniffed_packets = scapy.sniff(filter='ip', prn=process_packet, store=0)

if __name__ == '__main__':
    # Run the live packet capture function
    live_packet_capture()
