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
            self.ethType = types["etherTypes"][int("".join(data[12:14]),16)]
        except KeyError:
            self.ethType = "Unknown"

        self.sourceIP = formatIP(data[26:30])
        self.destinationIP = formatIP(data[30:34])

        if self.ethType == "IPv4":
            self.ipv4Protocol = types["ipv4Protocol"][int(data[23],16)]

        self.sourcePort = int("".join(data[34:36]),16)
        self.destinationPort = int("".join(data[36:38]),16)


        # TODO find app protocol
        try:
            if self.ipv4Protocol == "UDP":
                if  f"{self.sourcePort}" in types["udpProtocol"].keys():
                    self.appProtocol = types["udpProtocol"][str(self.sourcePort)]
                elif f"{self.destinationPort}" in types["udpProtocol"].keys():
                    self.appProtocol = types["udpProtocol"][str(self.destinationPort)]

            if self.ipv4Protocol=="TCP":
                if f"{self.sourcePort}" in types["tcpProtocol"].keys():
                    self.appProtocol = types["tcpProtocol"][str(self.sourcePort)]
                elif f"{self.destinationPort}" in types["tcpProtocol"].keys():
                   self.appProtocol = types["tcpProtocol"][str(self.destinationPort)]

        except AttributeError:
            pass

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
        text += f"Ether Type: {self.ethType}\n"
        if self.ethType == "IPv4":
            text+= f"IPv4 Protocol: {self.ipv4Protocol}\n"
        text += f"Source IP: {self.sourceIP}\n"
        text += f"Destination IP: {self.destinationIP}\n"
        try:
            if self.ipv4Protocol == "UDP" or self.ipv4Protocol == "TCP":
                text += f"Source Port: {self.sourcePort}\n"
                text += f"Destination Port: {self.destinationPort}\n"

                try:
                    text += f"App Protocol: {self.appProtocol}"
                except AttributeError:
                    print(f"<Error> {self.sourcePort} or {self.destinationPort} Port not part of Types.txt")
                    print(f"To show more ports add them to the txt")
                    print()

        except AttributeError:
            pass




        return text

