from Frame import Frame
from Types import types,initialize
class IeeeLLC(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "IEEE 802.3 LLC", sourceMAC, destinationMAC, data)
        initialize()
        self.sap = ""

        try:
            self.sap = types["saps"][int(data[14], 16)]  # from payload start byte
        except KeyError:
            print(f"wrong key helo <{int(data[14], 16)}>")
            self.sap = "NaN"

        self.totalLength = int("".join(data[12:14]), 16)

    def __str__(self):
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
               f"SAP: {self.sap}"