from Frame import Frame
from Types import pids
class IeeeSNAP(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "IEEE 802.3 LLC & SNAP", sourceMAC, destinationMAC, data)
        self.pid = ""

        if bin(int(data[16], 16))[-2:] == "11":  # lower two bits of the CF is 11, control field is 1 byte
            self.pid += pids[int("".join(data[20:22]), 16)]  # jump 3 bytes
        else:
            self.pid += pids[int("".join(data[21:23]), 16)]

    def getYAMLFormat(self):
        pass