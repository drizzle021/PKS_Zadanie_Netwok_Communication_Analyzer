class Frame:
    def __init__(self, number, length, frameType, sourceMAC, destMAC, data):
        self.frame_number = number + 1
        self.len_frame_pcap = length # length of frame in bytes
        self.len_frame_medium = max(64, length + 4) # ???
        self.frame_type = frameType # Ethernet II / IEEE
        self.src_mac = ":".join(sourceMAC) # MAC address
        self.dst_mac = ":".join(destMAC) # MAC address
        self.hexa_frame = ""

        for k, num in enumerate(data):
            if k % 16 == 0:
                self.hexa_frame =self.hexa_frame.rstrip()
                if k!=0:
                    self.hexa_frame+= "\n"
            self.hexa_frame+= f"{num} "

        self.hexa_frame = self.hexa_frame.rstrip()
        self.hexa_frame+="\n"

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
               f"{self.hexa_frame}"
