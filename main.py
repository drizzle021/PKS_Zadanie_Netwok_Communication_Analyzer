import sys

from scapy.utils import rdpcap
from scapy.all import raw

import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showinfo
from tkinter.filedialog import askopenfilename
from sys import exit

import re

from Frame import Frame

import ruamel.yaml


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
    return file

def getCleanRaw(frame, index) -> list:
    clean = re.findall("x[0-9,a-f]{2}", str(raw(frame[index])))

    for i in range(len(clean)):
        clean[i] = ((clean[i])[1:]).upper()

    """for k, num in enumerate(clean):
        if k % 16 == 0:
            print()
        print(num, end=" ")"""

    return clean


f = None
gui = GUI()
gui.start()

if f is None:
    print("File was not chosen")
    exit(1)


#Ether / IP / TCP 192.168.1.33:50032 > 147.175.1.55:http A


yaml = ruamel.yaml.YAML()
yaml.register_class(Frame)

frames = [Frame(i,
                len(f[i]),
                str(f[i]).split("/")[0],
                getCleanRaw(f,i)[:6],
                getCleanRaw(f,i)[6:12],
                getCleanRaw(f,i))
          for i in range(len(f))
          ]

print()
print()
for frame in frames:
    print(frame)
    print()

output = int(input("Gib sequence number of frame to output: "))
with open(f"frame_{output}.yaml",mode="w") as out:
    yaml.dump(frames[output],out)






