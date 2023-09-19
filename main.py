from scapy.utils import rdpcap
from scapy.all import raw

import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showinfo
from tkinter.filedialog import askopenfilename
from sys import exit

import re

from Frame import Frame

from ruamel.yaml import YAML


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

f = None
gui = GUI()
gui.start()

if f is None:
    print("File was not chosen")
    exit(1)


#Ether / IP / TCP 192.168.1.33:50032 > 147.175.1.55:http A

#frames = [Frame() for i in range(len(f))]

a = str(f[0]).split("/")

print(str(raw(f[0])))

b = re.findall("x[0-9,a-f]{2}",str(raw(f[0])))

for i in range(len(b)):
    b[i] = ((b[i])[1:]).upper()

for k,num in enumerate(b):
    if k%16==0:
        print()
    print(num, end=" ")

frames = [Frame(i,len(f[i]),"Eth",b[:6],b[6:12]) for i in range(len(f))]

"""print()
print()
for frame in frames:
    print(frame)
    print()"""

"""print(f"Number of frames: {len(f)}")
for i in (range(len(f)) if len(f) < 50 else range(50)):
    
    print(f"Sequence number: {i}")
    print(f"Length: {len(f[i])}")
    print(f[i])
    print(str(raw(f[i])))"""

#frame = Frame(1,125,"Ethernet II","22:2B:1D:2C:9A","22:2B:1D:2C:9A")





