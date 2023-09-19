class Frame:
    def __init__(self, number, length, frameType, source, dest):
        self.sequenceNumber = number
        self.length = length # length of frame in bytes
        self.type = frameType # Eth II, IEEE...
        self.source = ":".join(source) # MAC address
        self.destination = ":".join(dest) # MAC address
    def __str__(self):
        return f"Sequence Number: {self.sequenceNumber}\nFrame Length: {self.length}\nFrame Type: {self.type}" \
               f"\nSource: {self.source}\nDestination: {self.destination}"