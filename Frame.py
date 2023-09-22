from Types import types
from Types import pids,saps

class Frame:
    def __init__(self, number, length, frameType, sourceMAC, destMAC, data):
        self.frameNumber = number+1
        self.pcapLength = length # length of frame in bytes
        self.totalLength = None # ???
        self.type = frameType # Ethernet II / IEEE
        self.sourceMAC = ":".join(sourceMAC) # MAC address
        self.destinationMAC = ":".join(destMAC) # MAC address
        self.hexFrame = ""

        for k, num in enumerate(data):
            if k % 16 == 0:
                self.hexFrame+="\n"
            self.hexFrame+= f"{num} "

    def __str__(self):
        return f"Frame Number: {self.frameNumber}\n" \
               f"Frame .pcap Length: {self.pcapLength} B\n" \
               f"Frame Medium Length: {self.totalLength} B\n" \
               f"Frame Type: {self.type}\n" \
               f"Source: {self.sourceMAC}\n" \
               f"Destination: {self.destinationMAC}\n" \
               f"Hex:\n" \
               f"1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16\n" \
               "------------------------------------------------" \
               f"{self.hexFrame}"
