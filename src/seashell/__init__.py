import dataclasses
import json

# Initialize command blueprint 
@dataclasses.dataclass
class Command:
    name: str
    command: str
    meta: str

def make_cmd_class(name: str):
    """Wrapper to generate sub-command classes"""
    def __init__(self, from_: dict):
        Command.__init__(self, from_["name"], from_["command"], from_["meta"])
    return type(name, (Command,), {"__init__": __init__})

# Create sub-command classes
ReverseShell = make_cmd_class("ReverseShell")
BindShell = make_cmd_class("BindShell")
MSFVenom = make_cmd_class("MSFVenom")
HoaxShell = make_cmd_class("HoaxShell")

with open("data.json", "r") as fd:
    data = json.load(fd)

# Populate fields with appropriate sub-command class instancse
def populate_field(field: str, pclass: object) -> None:
    for index, cmd in enumerate(data[field]):
        data[field][index] = pclass(cmd)
    print(f"[*] Populated the `{field}` field.")
    return

populate_field("reverse", ReverseShell)
populate_field("bind", BindShell)
populate_field("msfvenom", MSFVenom)
populate_field("hoaxshell", HoaxShell)