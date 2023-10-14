from Communication import Communication
class TftpFilterFile:
    def __init__(self, fName, pcapName, frames):
        self.name = fName
        self.pcap_name = pcapName
        self.filter_name = "TFTP"
        self.packets = frames
        self.complete_comms = []

        self.findComms()
        delattr(self,"packets")

    def checkComms(self, connection):
        flag = 0
        comm = []
        part = []
        for frame in self.packets:
            if (frame.src_ip, frame.dst_ip) == connection or (frame.dst_ip, frame.src_ip) == connection:
                if frame.dst_port == 69:
                    part = []
                    flag = 1
                if flag == 1:
                    part.append(frame)
                if int("".join(frame.hexa_frame.replace("\n", " ").split(" ")[42:44]),16) == 5:
                    flag = 0
                    comm.append(part)



        return comm

    def findComms(self):
        connections = []

        for frame in self.packets:
            if (frame.src_ip, frame.dst_ip) not in connections and (frame.dst_ip, frame.src_ip) not in connections:
                connections.append((frame.src_ip, frame.dst_ip))

        completeCounter = 1
        for connection in connections:
            communications = self.checkComms(connection)
            for communication in communications:
                self.complete_comms.append(Communication(completeCounter,connection[0],connection[1], communication))
                completeCounter += 1


