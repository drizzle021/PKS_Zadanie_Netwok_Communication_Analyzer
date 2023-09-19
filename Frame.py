class Frame:
    def __init__(self, number, length, frameType, source, dest, data):
        self.sequenceNumber = number
        self.length = length # length of frame in bytes
        self.type = frameType.rstrip() # Eth II, IEEE...
        self.source = ":".join(source) # MAC address
        self.destination = ":".join(dest) # MAC address
        self.data = ""

        for k, num in enumerate(data):
                if k % 16 == 0:
                    self.data+="\n"
                self.data+= f"{num} "

    def __str__(self):
        return f"Sequence Number: {self.sequenceNumber}\n" \
               f"Frame Length: {self.length} Bytes\n" \
               f"Frame Type: {self.type}\n" \
               f"Source: {self.source}\n" \
               f"Destination: {self.destination}\n\n" \
               f"{self.data}"
