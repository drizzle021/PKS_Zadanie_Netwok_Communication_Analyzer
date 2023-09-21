from Frame import Frame
class Ethernet(Frame):
    def __init__(self, number, length, sourceMAC, destinationMAC, data):
        super().__init__(number, length, "Ethernet II", sourceMAC, destinationMAC, data)
        self.ethType = ""

    def getYAMLFormat(self):
        pass

