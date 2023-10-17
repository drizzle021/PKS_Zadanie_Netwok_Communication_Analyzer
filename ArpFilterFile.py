from Communication import Communication
class ArpFilterFile:
    def __init__(self, fName, pcapName, frames):
        self.name = fName
        self.pcap_name = pcapName
        self.filterName = "ARP"
        self.packets = frames
        self.complete_comms = []
        self.partial_comms = []

        self.findComms()
        # delete self.packets after done with filling the communications since we dont need it in the YAML
        delattr(self, "packets")

        # delete attributes if they arent used
        if not self.complete_comms:
            delattr(self, "complete_comms")
        if not self.partial_comms:
            delattr(self, "partial_comms")

    def checkComms(self, connection):
        comms = []
        for frame in self.packets:
            if (frame.src_ip, frame.dst_ip) == connection or (frame.dst_ip, frame.src_ip) == connection:
                comms.append(frame)

        complete = []
        partial = []

        while len(comms) > 0:
            try:
                if comms[-1].arp_opcode == "REPLY" and comms[-2].arp_opcode == "REQUEST":
                    complete.append(comms.pop(-1))
                    complete.append(comms.pop(-1))
                else:
                    partial.append(comms.pop(-1))
            except IndexError:
                partial.append(comms.pop(-1))

        return complete[::-1], partial[::-1]


    def findComms(self):
        connections = []

        for frame in self.packets:
            if (frame.src_ip, frame.dst_ip) not in connections and (frame.dst_ip, frame.src_ip) not in connections:
                connections.append((frame.src_ip, frame.dst_ip))
        print(connections)
        completeComms = []
        partialComms = []
        for connection in connections:
            comms = self.checkComms(connection)
            completeComms += comms[0]
            partialComms += comms[1]

        if completeComms:
            self.complete_comms.append(Communication(1, None, None, completeComms, True))
        if partialComms:
            self.partial_comms.append(Communication(1, None, None, partialComms, True))








