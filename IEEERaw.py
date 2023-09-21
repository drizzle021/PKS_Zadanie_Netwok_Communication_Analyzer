from Frame import Frame
class IeeeRaw(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "IEEE 802.3 Raw", sourceMAC, destinationMAC, data)

    def getYAMLFormat(self):
        pass