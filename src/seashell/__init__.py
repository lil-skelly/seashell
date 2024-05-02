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

# Create a logger object
logger = logging.getLogger(__name__)

# Configure logger
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
USING_OS = str() # windows, mac, linux
ADDRESS = [str(), int()] # IP, PORT
PAYLOAD_TYPE = str() # reverse, bind, msfvenom, hoaxshell
FILTERED_DATA = dict()
PAYLOAD = None # Command

dir_path = os.path.dirname(os.path.realpath(__file__))
data_file_path = os.path.join(dir_path, "data.json")
# Initialize command blueprint 
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
    return

for field in ["reverse", "bind", "msfvenom", "hoaxshell", "listeners"]:
    populate_field(field)
logger.debug(f"{CYAN}[*]{RESET} Populated {BOLD}fields{RESET}.")