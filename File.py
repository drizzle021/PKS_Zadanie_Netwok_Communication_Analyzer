from Senders import Sender
from WrongFilterException import WrongFilterException
from Types import types,initialize
initialize()

filterProtocols = [types["tcpProtocol"][protocol] for protocol in types["tcpProtocol"]] + \
                  [types["udpProtocol"][protocol] for protocol in types["udpProtocol"]] + \
                  [types["etherTypes"][protocol] for protocol in types["etherTypes"]]   + \
                  [types["ipv4Protocol"][protocol] for protocol in types["ipv4Protocol"]]

class File:
    def __init__(self, fName, pcapName,frames, filterName = ""):
        self.name = fName
        self.pcap_name = pcapName
        if filterName.strip() != "":
            if filterName.upper().strip() in filterProtocols:
                self.filter_name = filterName.upper().strip()
            else:
                raise WrongFilterException(filterName)
        self.packets = frames

        #TODO get rid of ipv4_senders field if theres no ipv4 in packets
        self.ipv4_senders = []
        # iterate through packets
        for i in self.packets:
            # use only ipv4 types
            if i.frame_type == "Ethernet II" and i.ether_type == "IPv4":
                # check if IP is already in the senders list
                if self.checkIP(i.src_ip):
                    # append if it's not in list
                    self.ipv4_senders.append(Sender(i.src_ip))
                else:
                    # if in the list find it and increment its sent packets
                    for sender in self.ipv4_senders:
                        if sender.node == i.src_ip:
                            sender.number_of_sent_packets += 1

        self.max_send_packets_by = self.findMax()



    # checks if IP is already in the sender list
    # returns False if in list, True if not in list
    def checkIP(self,ip):
        for i in self.ipv4_senders:
            if ip == i.node:
                return False
        return True

    # returns a list of the senders with the most packets sent
    def findMax(self):
        # sort the senders based on the packets sent
        sortedSenders = sorted(self.ipv4_senders, key=lambda sender: sender.number_of_sent_packets, reverse=True)
        max = []
        # check if any of the # of sent packets are same as the maximum
        for sender in sortedSenders:
            if sender.number_of_sent_packets == sortedSenders[0].number_of_sent_packets:
                max.append(sender.node)
            else:
                break
        return max

    def useFilter(self):
        filtered = []
        for frame in self.packets:
            try:
                if hasattr(frame, "app_protocol") and frame.app_protocol == self.filter_name:
                    filtered.append(frame)
                elif hasattr(frame, "protocol") and frame.protocol == self.filter_name:
                    filtered.append(frame)
                elif hasattr(frame, "ether_type") and frame.ether_type == self.filter_name:
                    filtered.append(frame)
            except AttributeError:
                continue

        self.packets = filtered



