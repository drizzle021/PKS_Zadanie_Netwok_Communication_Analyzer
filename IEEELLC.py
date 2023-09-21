from Frame import Frame
from Types import saps
class IeeeLLC(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "IEEE 802.3 LLC", sourceMAC, destinationMAC, data)
        self.sap = ""

        try:
            self.sap = saps[int(data[14], 16)]  # from payload start byte
        except KeyError:
            pass

    def getYAMLFormat(self):
        pass