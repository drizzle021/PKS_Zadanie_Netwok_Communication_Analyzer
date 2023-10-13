from Communication import Communication

class TcpFilterFile:
    def __init__(self, fName, pcapName, frames, filterName):
        self.name = fName
        self.pcap_name = pcapName
        self.filter_name = filterName
        self.packets = frames
        self.complete_comms = []
        self.partial_comms = []


        self.findComms()
        # delete self.packets after done with filling the communications since we dont need it in the YAML
        delattr(self,"packets")

        # delete attributes if they arent used
        if not self.complete_comms:
            delattr(self,"complete_comms")
        if not self.partial_comms:
            delattr(self,"partial_comms")

    def checkHandshake(self, connection) -> bool:
        handshake = ""
        opening = False
        ending = False
        # check 3-way handshake
        for frame in self.packets:
            if (frame.src_port,frame.dst_port) == connection or (frame.dst_port, frame.src_port) == connection:
                # concat flags converted to integers
                handshake += str(int(frame.hexa_frame.replace("\n", " ").split(" ")[47],16))
                handshake += " "
            # if the string contains the sequence of flags which represent SYN SYN+ACK ACK
            if "2 18 16" in handshake:
                opening = True
                break
        # if the handshake didnt happen return False since we already have a partial communication
        if not opening:
            return False

        # check ending
        handshake = ""
        for frame in self.packets:
            if (frame.src_port,frame.dst_port) == connection or (frame.dst_port, frame.src_port) == connection:
                handshake += str(int(frame.hexa_frame.replace("\n", " ").split(" ")[47],16))
                handshake += " "

        # split concatenated string into array for easier access
        handshake = handshake.split(" ")[:-1]

        # look at the last flags of the communications to find out if it was closed properly

        # RST
        if handshake[-1] == "4":
            ending = True

        # RST ACK
        elif handshake[-1] == "20":
            ending = True

        # FIN+ACK FIN+ACK ACK
        elif handshake[-1] == "16" and handshake[-2] == "17" and handshake[-3] == "17":
            ending = True

        # FIN+ACK ACK FIN+ACK ACK
        elif handshake[-1] == "16" and handshake[-2] == "17" and handshake[-3] == "16" and handshake[-4] == "17":
            ending = True


        # the communication is complete only if it was opened and closed appropriately
        # meaning both handshakes had to happen
        return opening and ending

    def findComms(self):
        connections = []

        # find all communications based on the used ports
        for frame in self.packets:
            if (frame.src_port,frame.dst_port) not in connections and (frame.dst_port,frame.src_port) not in connections:
                connections.append((frame.src_port, frame.dst_port))


        # counters used for creating Communication objects with serial numbers
        completeCounter = 0
        partialCounter = 0

        for connection in connections:
            frames = []
            # check opening and ending handshakes
            if self.checkHandshake(connection):
                completeCounter += 1
                # find all the frames of the communication
                for frame in self.packets:
                    if (frame.src_port, frame.dst_port) == connection or (frame.dst_port, frame.src_port) == connection:
                        frames.append(frame)

                self.complete_comms.append(Communication(completeCounter, frame.src_ip, frame.dst_ip, frames))
            else:
                partialCounter += 1
                # find all the frames of the communication
                for frame in self.packets:
                    if (frame.src_port, frame.dst_port) == connection or (frame.dst_port, frame.src_port) == connection:
                        frames.append(frame)

                self.partial_comms.append(Communication(partialCounter, frame.src_ip, frame.dst_ip, frames,partial=True))











