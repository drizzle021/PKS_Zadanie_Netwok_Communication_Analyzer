from Communication import Communication
class IcmpFilterFile:
    def __init__(self, fName, pcapName, frames):
        self.name = fName
        self.pcap_name = pcapName
        self.filter_name = "ICMP"
        self.packets = frames
        self.complete_comms = []
        self.partial_comms = []

        self.findComms()
        delattr(self,"packets")

        if not self.complete_comms:
            delattr(self,"complete_comms")
        if not self.partial_comms:
            delattr(self,"partial_comms")
        else:
            for comm in self.partial_comms:
                for frame in comm.packets:
                    delattr(frame, "icmp_type")
                    delattr(frame, "icmp_id")
                    delattr(frame, "icmp_seq")


    def checkComms(self, connection):
        print(connection)
        comms = []
        partial = []
        complete = []

        for frame in self.packets:
            is_fragmented = False
            if not hasattr(frame,"icmp_type"):
                is_fragmented = True
            if ((frame.src_ip, frame.dst_ip) == connection or (frame.dst_ip, frame.src_ip) == connection) and not is_fragmented and frame.icmp_type != "DESTINATION_UNREACHABLE":
                comms.append(frame)
            elif not is_fragmented and frame.icmp_type == "TIME_EXCEEDED" and len(comms) >= 1 and frame.icmp_id == comms[-1].icmp_id and frame.icmp_seq == comms[-1].icmp_seq:
                comms.append(frame)
            elif not is_fragmented and frame.icmp_type == "DESTINATION_UNREACHABLE":
                partial.append(frame)


        while len(comms) > 0:
            try:
                if comms[-1].icmp_id == comms[-2].icmp_id and comms[-1].icmp_seq == comms[-2].icmp_seq:
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
            if (frame.src_ip, frame.dst_ip) not in connections and (frame.dst_ip, frame.src_ip) not in connections and frame.icmp_type != "TIME_EXCEEDED":
                connections.append((frame.src_ip,frame.dst_ip))

        communications = []
        completeCounter = 1
        partialCounter = 1
        for connection in connections:
            comms = self.checkComms(connection)
            if comms[0]:
                self.complete_comms.append(Communication(completeCounter,connection[0],connection[1],comms[0]))
                completeCounter += 1
            if comms[1]:
                self.partial_comms.append(Communication(partialCounter, connection[0], connection[1], comms[1], partial=True))



