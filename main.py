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

def openFile(fname):
    file = rdpcap(fname)
    print(fname.split("/")[-1])
    return tuple([fname, file])

def getCleanRaw(frame, index) -> list:
    clean = str(raw(frame[index]).hex(" ")).upper().split(" ")
    return clean

def indentifyType(index, hexFrame, iframe):
    joint = int("".join(hexFrame[12:14]),16)
    if joint >= 1536:
        return Ethernet(index, len(iframe[index]),hexFrame[:6], hexFrame[6:12], hexFrame)
    elif joint <= 1500:
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

frames = [indentifyType(i,getCleanRaw(f,i),f)
          for i in range(len(f))
          ]


file = File("test.yaml", filename,frames)


print()
print()
for frame in frames:
    print(frame)
    print()


for i in range(len(file.packets)):
    file.packets[i].hexa_frame = LiteralScalarString(textwrap.dedent(file.packets[i].hexa_frame))

with open("test.yaml",mode="w") as out:
    yaml.dump(file,out)

lines = []
with open("test.yaml",mode="r") as out:
    lines = out.readlines()

with open("test.yaml",mode="w") as out:
    flag = 0
    for k,line in enumerate(lines):
        """if line.find("|2") >= 0 :
            line = line.replace("|2","|")"""

        if line.find("!") == -1 :
            if flag == 1:
                out.write("- "+line)
                flag = 2
            elif flag == 2:
                out.write("  "+line)
            else:
                out.write(line)
        else:
            if k != 0:
                flag = 1