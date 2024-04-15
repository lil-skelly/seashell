import logging
import dataclasses
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
logger.setLevel(logging.DEBUG)

CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

dir_path = os.path.dirname(os.path.realpath(__file__))
data_file_path = os.path.join(dir_path, "data.json")
print(data_file_path)
# Initialize command blueprint 
@dataclasses.dataclass
class Command:
    name: str
    command: str
    meta: str




with open(data_file_path, "r") as fd:
    data = json.load(fd)

# Populate fields with appropriate sub-command class instancse
def populate_field(field: str) -> None:
    for index, cmd in enumerate(data[field]):
        data[field][index] = Command(**cmd)
    logger.info(f"{CYAN}[*]{RESET} Populated {BOLD}`{field}`{RESET} field.")
    return

for field in ["reverse", "bind", "msfvenom", "hoaxshell"]:
    populate_field(field)

print(data["reverse"][0])