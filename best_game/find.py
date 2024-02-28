from scapy.layers.tls.cert import PrivKey
from scapy.layers.tls.session import *
from scapy.all import *
from scapy.layers.tls.record import TLS

# find best game
if __name__ == '__main__':

    load_layer("tls")

    pcapFile = "/home/elifyildiz/Desktop/best_game/best_game.pcap"
    pcapFile2 = "/home/elifyildiz/Desktop/best_game/best_game_tls1_3.pcap"
    privateKey = "/home/elifyildiz/Desktop/best_game/server.key"
    keystr = open(privateKey, 'rb').read()
    packets = rdpcap(pcapFile)
    packets2 = rdpcap(pcapFile2)

    privKeyObject = PrivKey(privateKey)

    res = sniff(offline=packets, session=TLSSession(server_rsa_key=privKeyObject))

    res2 = sniff(offline=packets2, session=TLSSession(server_rsa_key=privKeyObject))

    for index, s in enumerate(res):
        s.show()

    print("------------------------------second file:--------------------------------------------")

    for index, s in enumerate(res2):
        s.show()
    print("-------------------------------third file:")

    

    a = res2[7].getlayer(TLS, 2).msg[0].data
    print(bytes.fromhex(a.decode('utf-8')))


    print("Decrypted Packets from second file:")
    for packet in packets2:
        if TLS in packet:
            # Decode bytes to string using UTF-8 encoding
            payload_str = packet[TLS].payload.decode('utf-8', errors='ignore')

            print(payload_str)

# https://www.programcreek.com/python/?CodeExample=load%20private%20key
# https://stackoverflow.com/questions/72879385/how-to-use-scapy-to-decrypt-tls-traffic-and-print-the-http-headers
# https://github.com/secdev/scapy/blob/3040f6d705176731494a7bcf76b820f077716729/test/tls.uts#L1166-L1218
# https://supermariobros.io
