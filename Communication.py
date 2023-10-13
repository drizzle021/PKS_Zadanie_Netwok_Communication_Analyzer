class Communication:
    def __init__(self, n, src, dst, frames, partial=False):
        self.number_comm = n
        self.src_comm = src
        self.dst_comm = dst
        self.packets = frames

        if partial:
            delattr(self,"src_comm")
            delattr(self,"dst_comm")

