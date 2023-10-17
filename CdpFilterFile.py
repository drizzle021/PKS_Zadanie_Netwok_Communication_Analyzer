class CdpFilterFile:
    def __init__(self, fName, pcapName, frames,filterName):
        self.name = fName
        self.pcap_name = pcapName
        self.filter_name = filterName
        self.packets = frames
        print(self.packets)
        self.number_of_frames = len(self.packets)
