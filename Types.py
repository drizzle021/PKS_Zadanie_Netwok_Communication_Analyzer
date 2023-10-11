types = {}

# reads and formats the types.txt into a dictionary
def initialize():
    global types
    with open("Protocols/Types.txt", mode="r") as f:
        for line in f:
            line = line.rstrip()
            if line[0] != "#":
                key, value = tuple(line.split(" "))
                if key[1] == "x":
                    key = int(key[key.index("x") + 1:], 16)
                types[name].update({key: value})
            else:
                types.update({line[1:]: dict()})
                name = line[1:]

