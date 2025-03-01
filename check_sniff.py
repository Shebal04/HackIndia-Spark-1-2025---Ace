import scapy.all as scapy

def test_sniff(packet):
    print("Packet captured:", packet.summary())

print("Testing packet capture...")
scapy.sniff(prn=test_sniff, count=5, store=False)
