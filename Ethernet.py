from Frame import Frame
from Types import types,initialize
class Ethernet(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "Ethernet II", sourceMAC, destinationMAC, data)
        initialize()
        self.ethType = types["etherTypes"][int("".join(data[12:14]),16)]

        if self.ethType != "ARP":
            self.totalLength = int("".join(data[16:18]),16)

    def __str__(self):
        if self.ethType != "ARP":
            return f"Frame Number: {self.frameNumber}\n" \
               f"Frame .pcap Length: {self.pcapLength} B\n" \
               f"Frame Total Length: {self.totalLength} B\n" \
               f"Frame Type: {self.type}\n" \
               f"Source: {self.sourceMAC}\n" \
               f"Destination: {self.destinationMAC}\n" \
               f"Hex:\n" \
               f"1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16\n" \
               "------------------------------------------------" \
               f"{self.hexFrame}\n" \
               f"Ether Type: {self.ethType}"
        else:
            return  f"Frame Number: {self.frameNumber}\n" \
                    f"Frame .pcap Length: {self.pcapLength} B\n" \
                    f"Frame Type: {self.type}\n" \
                    f"Source: {self.sourceMAC}\n" \
                    f"Destination: {self.destinationMAC}\n" \
                    f"Hex:\n" \
                    f"1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16\n" \
                    "------------------------------------------------" \
                    f"{self.hexFrame}\n" \
                    f"Ether Type: {self.ethType}"

