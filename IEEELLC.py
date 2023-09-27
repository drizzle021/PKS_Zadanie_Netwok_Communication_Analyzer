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
            self.sap = "semmi"

    def __str__(self):
        return f"Frame Number: {self.frame_number}\n" \
               f"Frame .pcap Length: {self.len_frame_pcap} B\n" \
               f"Frame Medium Length: {self.len_frame_medium} B\n" \
               f"Frame Type: {self.frame_type}\n" \
               f"Source: {self.src_mac}\n" \
               f"Destination: {self.dst_mac}\n" \
               f"Hex:\n" \
               f"1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16\n" \
               "------------------------------------------------\n" \
               f"{self.hexa_frame}\n" \
               f"SAP: {self.sap}"