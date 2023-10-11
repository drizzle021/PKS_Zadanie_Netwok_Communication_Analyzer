class Sender:
    def __init__(self, ip):
        self.node = ip
        self.number_of_sent_packets = 1

    def __str__(self):
        return f"node: {self.node}\n" \
               f"number of packets {self.number_of_sent_packets}\n"
