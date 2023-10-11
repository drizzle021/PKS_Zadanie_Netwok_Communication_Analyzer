from Frame import Frame
from Types import types,initialize

def formatIP(hexCode):
    ip = []
    for i in hexCode:
        ip.append(str(int(i,16)))

    return ".".join(ip)

class Ethernet(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "Ethernet II", sourceMAC, destinationMAC, data)
        initialize()
        try:
            self.ether_type = types["etherTypes"][int("".join(data[12:14]), 16)]
        except KeyError:
            self.ether_type = "Unknown"

        # if ether_type is ARP we need to jump some bytes
        if self.ether_type == "ARP":
            if int(data[21], 16) == 1:
                self.arp_opcode = "REQUEST"
            elif int(data[21], 16) == 2:
                self.arp_opcode = "REPLY"
            self.src_ip = formatIP(data[28:32])
            self.dst_ip = formatIP(data[38:42])

        else:
            self.src_ip = formatIP(data[26:30])
            self.dst_ip = formatIP(data[30:34])

        if self.ether_type == "IPv4":
            self.protocol = types["ipv4Protocol"][int(data[23], 16)]

        if self.ether_type!= "ARP":
            self.src_port = int("".join(data[34:36]), 16)
            self.dst_port = int("".join(data[36:38]), 16)

        try:
            if self.protocol == "UDP":
                if  f"{self.src_port}" in types["udpProtocol"].keys():
                    self.app_protocol = types["udpProtocol"][str(self.src_port)]
                elif f"{self.dst_port}" in types["udpProtocol"].keys():
                    self.app_protocol = types["udpProtocol"][str(self.dst_port)]

            if self.protocol== "TCP":
                if f"{self.src_port}" in types["tcpProtocol"].keys():
                    self.app_protocol = types["tcpProtocol"][str(self.src_port)]
                elif f"{self.dst_port}" in types["tcpProtocol"].keys():
                   self.app_protocol = types["tcpProtocol"][str(self.dst_port)]

        except AttributeError:
            pass

    # string representation of the Object
    def __str__(self):
        text = ""
        text += f"Frame Number: {self.frame_number}\n"
        text += f"Frame .pcap Length: {self.len_frame_pcap} B\n"
        text += f"Frame Medium Length: {self.len_frame_medium} B\n"
        text += f"Frame Type: {self.frame_type}\n"
        text += f"Source: {self.src_mac}\n"
        text += f"Destination: {self.dst_mac}\n"
        text += f"Hex:\n"
        text += f"1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16\n"
        text += "------------------------------------------------\n"
        text += f"{self.hexa_frame}\n"
        text += f"Ether Type: {self.ether_type}\n"
        if self.ether_type == "ARP":
            text+= f"ARP Opode: {self.arp_opcode}\n"
        if self.ether_type == "IPv4":
            text+= f"IPv4 Protocol: {self.protocol}\n"
        text += f"Source IP: {self.src_ip}\n"
        text += f"Destination IP: {self.dst_ip}\n"
        try:
            if self.protocol == "UDP" or self.protocol == "TCP":
                text += f"Source Port: {self.src_port}\n"
                text += f"Destination Port: {self.dst_port}\n"

                try:
                    text += f"App Protocol: {self.app_protocol}"
                except AttributeError:
                    print(f"<Error> {self.src_port} or {self.dst_port} Port not part of Types.txt")
                    print(f"To show more ports add them to the txt")
                    print()

        except AttributeError:
            pass




        return text

