from random import randint
class Sender:
    def __init__(self, ip=None, packets = None):
        self.node = ".".join([str(randint(0,256)) for i in range(4)])
        self.numberOfPackets = randint(10,60)