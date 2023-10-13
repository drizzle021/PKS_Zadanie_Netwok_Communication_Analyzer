from File import File
class Communication:
    def __init__(self, n, frames):
        self.number_comm = n
        self.packets = frames


class ArpFilterFile:
    def __init__(self, fName, pcapName, frames):
        self.name = fName
        self.pcap_name = pcapName
        self.filterName = "ARP"
        self.complete_comms = []
        self.partial_comms = []

        self.findComms(frames)


    def findComms(self,frames):
        requests = dict()
        for frame in frames:
            if frame.arp_opcode == "REQUEST":
                if frame.dst_ip not in requests.keys():
                    requests.update({frame.dst_ip:[1,frame]})
                else:
                    requests[frame.dst_ip][0] += 1
                    requests[frame.dst_ip].append(frame)


        for request in requests:
            k = requests[request][0]
            f = []
            for frame in frames:
                if frame.src_ip == request and frame.arp_opcode == "REPLY":
                    f.append(requests[request].pop(1))
                    f.append(frame)
                    k -= 1
                if k == 0:
                    self.complete_comms.append(Communication(1,f))
                    break







