from Frame import Frame
from Types import types,initialize
class IeeeSNAP(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "IEEE 802.3 LLC & SNAP", sourceMAC, destinationMAC, data)
        initialize()
        self.pid = ""

        if bin(int(data[16], 16))[-2:] == "11":  # lower two bits of the CF is 11, control field is 1 byte
            self.pid += types["pids"][int("".join(data[20:22]), 16)]  # jump 3 bytes
        else:
            self.pid += types["pids"][int("".join(data[21:23]), 16)]

        #self.totalLength = int("".join(data[12:14]), 16)

    def __str__(self):
        return f"Frame Number: {self.frame_number}\n" \
               f"Frame .pcap Length: {self.len_frame_pcap} B\n" \
               f"Frame Medium Length: {self.len_frame_medium} B\n" \
               f"Frame Type: {self.frame_type}\n" \
               f"Source: {self.src_mac}\n" \
               f"Destination: {self.dst_mac}\n" \
               f"Hex:\n" \
               f"1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16\n" \
               "------------------------------------------------" \
               f"{self.hexa_frame}\n" \
               f"PID: {self.pid}"