import textwrap
from sys import exit

from WrongFilterException import WrongFilterException
from Frame import Frame
from File import File
from ArpFilterFile import ArpFilterFile
from TcpFilterFile import TcpFilterFile
from TftpFilterFile import TftpFilterFile
from IcmpFilterFile import IcmpFilterFile
from CdpFilterFile import CdpFilterFile
from Communication import Communication
from Senders import Sender
from Ethernet import Ethernet
from IEEERaw import IeeeRaw
from IEEELLC import IeeeLLC
from IEEESNAP import IeeeSNAP

from scapy.utils import rdpcap
from scapy.all import raw
import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString

import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showerror
from tkinter.filedialog import askopenfilename

from Types import types,initialize

CONSOLE_OUTPUT = False
initialize()

filterProtocols = [types["tcpProtocol"][protocol] for protocol in types["tcpProtocol"]] + \
                  [types["udpProtocol"][protocol] for protocol in types["udpProtocol"]] + \
                  [types["etherTypes"][protocol] for protocol in types["etherTypes"]]   + \
                  [types["ipv4Protocol"][protocol] for protocol in types["ipv4Protocol"] ]+ ["CDP"]

# minimal GUI for file selection
class GUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("PKS - Communication Analyzer")
        self.geometry("400x170")
        self.resizable(False, False)

        self.space0 = ttk.Label(text="")
        self.space0.grid(row=0)

        self.fileLabel = ttk.Label(self, text="File Path:",font=("Arial",12),anchor="w",justify="left",width= 10)
        self.fileLabel.grid(column=1,row=1,padx=40, sticky="W")

        self.space1 = ttk.Label(text="")
        self.space1.grid(row=2)

        self.fButton = ttk.Button(self, text="Select File")
        self.fButton["command"] = self.selectFile
        self.fButton.grid(pady=4,column=2,row=3)

        self.inputField = ttk.Entry(self)
        self.inputField.grid(column=2,row=1 )


        self.filterLabel = ttk.Label(self, text="Filter Parameter:",font=("Arial",12),anchor="w",justify="left")
        self.filterLabel.grid(pady=4, padx=40,row=4,column=1,sticky="W")

        self.inputFieldFilter = ttk.Entry(self)
        self.inputFieldFilter.grid(row=4,column=2)

        self.space2 = ttk.Label(text="")
        self.space2.grid(row=5)

        self.button = ttk.Button(self, text="Open and Analyze")
        self.button["command"] = self.submit
        self.button.grid(row=6,column=2)

    def selectFile(self):
        filename = askopenfilename()
        self.inputField.delete(0, tk.END)
        self.inputField.insert(0, filename)

    def submit(self):
        global f
        inp = self.inputField.get()
        error = False
        #showinfo(title='Information', message=f'Submitted: {inp}')
        try:
            f = tuple(openFile(inp) + [self.inputFieldFilter.get().upper().strip()])
            if self.inputFieldFilter.get().upper().strip() not in filterProtocols and self.inputFieldFilter.get().upper().strip() != "" :
                showerror(title='Error', message=f"Protocol <{self.inputFieldFilter.get().strip()}> is not in external file Types.txt")
                raise WrongFilterException(self.inputFieldFilter.get().strip())
        except FileNotFoundError:
            error = True
            showerror(title='Error', message=f"Please choose a .pcap file before starting the analysis")

        if not error:
            self.destroy()
    def start(self):
        self.mainloop()

# opens .pcap file and returns a tuple with the file and its name
def openFile(fname):
    file = rdpcap(fname)
    print(fname.split("/")[-1])
    return [fname, file]
# clean up the byte string
def getCleanRaw(frame, index) -> list:
    clean = str(raw(frame[index]).hex(" ")).upper().split(" ")
    return clean

# identifies if the frame is ETHERNET or IEEE 802.3
def indentifyType(index, hexFrame, iframe):
    # check if theres an ISL frame by looking at the destination bytes
    if " ".join(hexFrame[:6]) == "01 00 0C 00 00 00" or " ".join(hexFrame[:6]) == "03 00 0C 00 00 00":
        hexFrame = hexFrame[25:]


    joint = int("".join(hexFrame[12:14]), 16)

    # if the joint bytes are >= 1536 it's ETHERNET. If <= 1500 its IEEE 802.3
    if joint >= 1536:
        return Ethernet(index, len(iframe[index]),hexFrame[:6], hexFrame[6:12], hexFrame)

    elif joint <= 1500:
        # check payload's first two bytes
        if "".join(hexFrame[14:16]) == "AAAA":
            return IeeeSNAP(index, len(iframe[index]),hexFrame[:6], hexFrame[6:12], hexFrame)

        elif "".join(hexFrame[14:16]) == "FFFF":
            return IeeeRaw(index, len(iframe[index]),hexFrame[:6], hexFrame[6:12], hexFrame)

        else:
            return IeeeLLC(index, len(iframe[index]),hexFrame[:6], hexFrame[6:12], hexFrame)

def useFilter(frames, filterName):
    filtered = []
    if filterName == "TFTP":
        filterName = "UDP"

    for frame in frames:
        try:
            if hasattr(frame, "app_protocol") and frame.app_protocol == filterName:
                filtered.append(frame)
            elif hasattr(frame, "protocol") and frame.protocol == filterName:
                filtered.append(frame)
            elif hasattr(frame, "ether_type") and frame.ether_type == filterName:
                filtered.append(frame)
            elif hasattr(frame,"pid") and frame.pid == filterName:
                filtered.append(frame)
        except AttributeError:
            continue

    return filtered

def getFileType(fileName, filteredFrames, filterName):
    if filterName == "ARP":
        return ArpFilterFile("PKS2023_24",fileName,filteredFrames)
    elif filterName == "TFTP":
        return TftpFilterFile("PKS2023_24", fileName, filteredFrames)
    elif filterName == "ICMP":
        return IcmpFilterFile("PKS2023_24", fileName, filteredFrames)
    elif filterName in types["tcpProtocol"].values() or filterName == "TCP":
        return TcpFilterFile("PKS2023_24",fileName,filteredFrames,filterName)
    elif filterName == "CDP":
        return CdpFilterFile("PKS2023_24",fileName,filteredFrames,filterName)
    else:
        return File("PKS2023_24", filename,frames,filterName=filterName)



f = ""
gui = GUI()
gui.start()

# if file is not chosen exit the program ¯\_(ツ)_/¯  <- shrug ascii art
if f == "":
    print("File was not chosen")
    exit(1)

filename, f, filterName = f

filename = filename.split("/")[-1]

yaml = ruamel.yaml.YAML()
yaml.register_class(Frame)
yaml.register_class(File)
yaml.register_class(ArpFilterFile)
yaml.register_class(TcpFilterFile)
yaml.register_class(TftpFilterFile)
yaml.register_class(IcmpFilterFile)
yaml.register_class(CdpFilterFile)
yaml.register_class(Sender)
yaml.register_class(Ethernet)
yaml.register_class(IeeeSNAP)
yaml.register_class(IeeeLLC)
yaml.register_class(IeeeRaw)
yaml.register_class(Communication)

# Create Frame objects
frames = [indentifyType(i,getCleanRaw(f,i),f)
          for i in range(len(f))
          ]
if filterName != "":
    frames = useFilter(frames,filterName)


file = getFileType(filename,frames,filterName)

#console output
if CONSOLE_OUTPUT:
    print()
    print()
    for frame in frames:
        print(frame)
        print()

# fix the hexaframe, so it retains block style 16 bytes/line
if filterName == "ARP" or filterName in types["tcpProtocol"].values() or filterName == "ICMP" or filterName == "TCP":
    if hasattr(file, "complete_comms"):
        for comm in file.complete_comms:
            for i in range(len(comm.packets)):
                comm.packets[i].hexa_frame = LiteralScalarString(textwrap.dedent(comm.packets[i].hexa_frame))
    if hasattr(file, "partial_comms"):
        for comm in file.partial_comms:
            for i in range(len(comm.packets)):
                comm.packets[i].hexa_frame = LiteralScalarString(textwrap.dedent(comm.packets[i].hexa_frame))
elif filterName == "TFTP":
    if hasattr(file,"complete_comms"):
        for comm in file.complete_comms:
            for i in range(len(comm.packets)):
                comm.packets[i].hexa_frame = LiteralScalarString(textwrap.dedent(comm.packets[i].hexa_frame))

elif filterName == "CDP":
    for packet in file.packets:
        packet.hexa_frame = LiteralScalarString(textwrap.dedent(packet.hexa_frame))

else:
    for i in range(len(file.packets)):
        file.packets[i].hexa_frame = LiteralScalarString(textwrap.dedent(file.packets[i].hexa_frame))

# create yaml file
with open(file.name+".yaml",mode="w") as out:
    yaml.dump(file,out)

# read the yaml file
with open(file.name+".yaml",mode="r") as out:
    lines = out.readlines()

# reformat the file for the validator
with open(file.name+".yaml",mode="w") as out:
    flag = 0
    for k,line in enumerate(lines):
        if line.rstrip() == f"name: {file.name}":
            line = line.replace("_","/")

        if line.find("!") == -1 :   # removing class tags
            if flag == 1:
                out.write("- "+line) # remove hyphens at the start of lines after class tags
                flag = 2
            # fix ipv4 sender analysis
            elif line.strip() == "ipv4_senders:" or line.strip() == "max_send_packets_by:" or line.strip() == "partial_comms:":
                out.write(line.lstrip())
            elif flag == 2:
                if "number_of_frames" in line:
                    out.write(line.lstrip())
                else:
                    out.write("  "+line) # add indents if hyphen was removed


            else:
                out.write(line)

        else:
            if k != 0:
                flag = 1

if filterName.strip() != "" and filterName!= "CDP":
    with open(file.name+".yaml",mode="r") as out:
        lines = out.readlines()

    with open(file.name+".yaml",mode="w") as out:

        flag = 0

        for line in lines:
            if line.strip() == "packets:":
                flag = 1
                out.write(line)
                continue

            if "number_comm:" in line or "partial_comm" in line:
                out.write(line)
                flag = 0
                continue


            if flag == 1:
                if "frame_number" in line:
                    out.write("      - " + line[:line.index(":")].replace(" ","")[1:]+line[line.index(":"):])
                else:
                    out.write("  " + line)
            else:
                out.write(line)


