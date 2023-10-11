from File import File
class ArpFilterFile(File):
    def __init__(self, fName, pcapName, frames):
        super().__init__(fName, pcapName, frames, "ARP")

