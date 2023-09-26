import textwrap
from sys import exit
from Frame import Frame
from File import File
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
from tkinter.messagebox import showinfo
from tkinter.filedialog import askopenfilename

# minimal GUI for file selection
class GUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("PKS - FileOpen")
        self.geometry("200x150")
        self.resizable(False, False)

        self.fButton = ttk.Button(self, text="Select File")
        self.fButton["command"] = self.selectFile
        self.fButton.pack()

        self.inputField = ttk.Entry(self)
        self.inputField.pack()

        self.button = ttk.Button(self, text="Open")
        self.button["command"] = self.submit
        self.button.pack()



    def selectFile(self):
        filename = askopenfilename()
        self.inputField.delete(0, tk.END)
        self.inputField.insert(0, filename)

    def submit(self):
        global f
        inp = self.inputField.get()
        #showinfo(title='Information', message=f'Submitted: {inp}')

        f = openFile(inp)


        self.destroy()


    def start(self):
        self.mainloop()

# opens .pcap file and returns a tuple with the file and its name
def openFile(fname):
    file = rdpcap(fname)
    print(fname.split("/")[-1])
    return tuple([fname, file])

# clean up the byte string
def getCleanRaw(frame, index) -> list:
    clean = str(raw(frame[index]).hex(" ")).upper().split(" ")
    return clean

# identifies if the frame is ETHERNET or IEEE 802.3
def indentifyType(index, hexFrame, iframe):
    joint = int("".join(hexFrame[12:14]),16)

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

f = ""
gui = GUI()
gui.start()


if f == "":
    print("File was not chosen")
    exit(1)

filename, f = f

filename = filename.split("/")[-1]

yaml = ruamel.yaml.YAML()
yaml.register_class(Frame)
yaml.register_class(File)
yaml.register_class(Sender)
yaml.register_class(Ethernet)
yaml.register_class(IeeeSNAP)
yaml.register_class(IeeeLLC)
yaml.register_class(IeeeRaw)

# Create Frame objects
frames = [indentifyType(i,getCleanRaw(f,i),f)
          for i in range(len(f))
          ]

file = File("PKS2023_24", filename,frames)

#console output
"""print()
print()
for frame in frames:
    print(frame)
    print()
"""
# fix the hexaframe, so it retains block style 16 bytes/line
for i in range(len(file.packets)):
    file.packets[i].hexa_frame = LiteralScalarString(textwrap.dedent(file.packets[i].hexa_frame))

# create yaml file
with open(file.name+".yaml",mode="w") as out:
    yaml.dump(file,out)

# read the yaml file
lines = []
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
            elif flag == 2:
                out.write("  "+line) # add indents if hyphen was removed
            else:
                out.write(line)
        else:
            if k != 0:
                flag = 1