from Senders import Sender
class File:
    def __init__(self, fName, pcapName,frames):
        self.fName = fName
        self.pcapName = pcapName
        self.packets = frames


        self.ipv4Senders = [Sender() for i in range(5)]
        self.maxSendPackets = []