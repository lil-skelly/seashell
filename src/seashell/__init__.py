import logging
import dataclasses
import itertools
import json
import os

# Initialize logger
class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors"""

    format = "%(message)s"
    FORMATS = {
        logging.DEBUG: format,  # White
        logging.INFO: format,  # Cyan
        logging.ERROR: format,  # Red
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Initialize logger
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(CustomFormatter())
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

# Initialize global scope variables
USING_OS = "" # windows, mac, linux
ADDRESS = ["", 0] # IP, PORT
PAYLOAD_TYPE = "" # reverse, bind, msfvenom, hoaxshell
FILTERED_DATA = {}
PAYLOAD = None # Command
ENCODER = "" # base64 / xor encoder for payload

dir_path = os.path.dirname(os.path.realpath(__file__))
data_file_path = os.path.join(dir_path, "data.json")

@dataclasses.dataclass()
class Command:
    name: str
    command: str
    meta: str
    id: int = dataclasses.field(default_factory=itertools.count().__next__)

with open(data_file_path, "r") as fd:
    data = json.load(fd)

# Populate fields with appropriate sub-command class instancse
def populate_field(field: str) -> None:
    for index, cmd in enumerate(data[field]):
        data[field][index] = Command(**cmd)

def populate_fields(fields: tuple[str]) -> None:
    for field in fields:
        for index, cmd in enumerate(data[field]):
            data[field][index] = Command(**cmd)

populate_fields(("reverse", "bind", "msfvenom", "hoaxshell", "listeners"))
# populate_fields(("reverse", "bind", "msfvenom", "hoaxshell", "listeners"))
logger.debug(f"{CYAN}[*]{RESET} Populated {BOLD}fields{RESET}.")
