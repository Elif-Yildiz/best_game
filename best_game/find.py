from scapy.layers.tls.cert import PrivKey  # In order to use the server key this import is needed
from scapy.layers.tls.session import *  # For reading tls layers
from scapy.all import * # For using scapy to read pcaps
from scapy.layers.tls.record import TLS

# find best game
if __name__ == '__main__':

    load_layer("tls")  # packet.show() -> the raw data seen there is tls layer, in order to see that load tls layers

    pcapFile = "/home/elifyildiz/Desktop/best_game/best_game.pcap"  # destination of pcap file
    pcapFile2 = "/home/elifyildiz/Desktop/best_game/best_game_tls1_3.pcap"
    privateKey = "/home/elifyildiz/Desktop/best_game/server.key"  # destination of server rsa key
    keystr = open(privateKey, 'rb').read()  # to use key, reading binary
    packets = rdpcap(pcapFile)  # reading pcap file
    packets2 = rdpcap(pcapFile2)

    privKeyObject = PrivKey(privateKey)  # assigning key as private key object,so I can use while sniffing

    res = sniff(offline=packets, session=TLSSession(server_rsa_key=privKeyObject))
    # decrypting packet's tls layers with our key

    res2 = sniff(offline=packets2, session=TLSSession(server_rsa_key=privKeyObject))

    # from scapy terminal len(packets) -> 40 which means there are 40 packets in this pcap file
    for index, s in enumerate(res):  # showing all packets individually to analyze better
        s.show()

    print("Answer:")
    answer = res[13]
    answer.show()
'''
When you reach 13th packet, you find a link for a game: https://supermariobros.io
###[ Ethernet ]### 
  dst       = 52:a6:00:8c:aa:8e
  src       = a6:6d:a4:6f:37:9d
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 169
     id        = 20188
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x44c0
     src       = 10.200.201.33
     dst       = 10.200.200.1
     \options   \
###[ TCP ]### 
        sport     = https
        dport     = 43690
        seq       = 398687390
        ack       = 1439286055
        dataofs   = 8
        reserved  = 0
        flags     = PA
        window    = 501
        chksum    = 0xa74e
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (688807467, 2704132283))]
###[ TLS ]### 
           type      = application_data
           version   = TLS 1.2
           len       = 112    [deciphered_len= 72]
           iv        = b'\x0e\x1d\x01kq\x9b\xa3\xa7s\x16b\xd2\x8d\x82\xc3\x8b'
           \msg       \
            |###[ TLS Application Data ]### 
            |  data      = 'HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\nhttps://supermariobros.io/\n'
           mac       = b'\x01\x98R\xab\x7f\xb3 \x10\x14&\xc0\xa8\x0c\xec\xbe\xd2\xdf\x16\x97u'
           pad       = b'\x03\x03\x03'
           padlen    = 3
'''

'''
# print("------------------------------second file:--------------------------------------------")

# for index, s in enumerate(res2):
#    s.show()


    a = res2[7].getlayer(TLS, 2).msg[0].data
    print(bytes.fromhex(a.decode('utf-8')))


    print("Decrypted Packets from second file:")
    for packet in packets2:
        if TLS in packet:
            # Decode bytes to string using UTF-8 encoding
            payload_str = packet[TLS].payload.decode('utf-8', errors='ignore')

            print(payload_str)
            
'''

# Links: Resources I used
# https://www.programcreek.com/python/?CodeExample=load%20private%20key
# https://stackoverflow.com/questions/72879385/how-to-use-scapy-to-decrypt-tls-traffic-and-print-the-http-headers
# https://github.com/secdev/scapy/blob/3040f6d705176731494a7bcf76b820f077716729/test/tls.uts#L1166-L1218
# Finding:
# https://supermariobros.io

'''
    Control Bits: 6 bits (from left to right):

        URG: Urgent Pointer field significant
        ACK: Acknowledgment field significant
        PSH: Push Function
        RST: Reset the connection
        SYN: Synchronize sequence numbers
        FIN: No more data from sender

        NS: ECN-nonce - concealment protection. RFC 3540
        CWR: Congestion window reduced. RFC 3168
        ECE: ECN-Echo. RFC 3168
    
        TCP:RA = RST, ACK
        TCP:FA = FIN, ACK


'''
