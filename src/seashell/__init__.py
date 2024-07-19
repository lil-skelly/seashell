import logging
import dataclasses
import itertools
import json
import os

# Initialize logger
class CustomFormatter(logging.Formatter):
    """Logging formatter to add colors"""

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

def load_json_data(data_file_path: str) -> dict:
    """Load JSON data from a specified file path.

    Parameters
    ----------
    data_file_path : str
        Path to the data file

    Returns
    -------
    dict
        _description_
    """
    try:
        with open(data_file_path, "r") as fd:
            data = json.load(fd)
    except FileNotFoundError:
        logger.critical(f"{RED}{BOLD}[!!!]{RESET} {data_file_path} not found.")
    except json.JSONDecodeError:
        logger.critical(f"{RED}{BOLD}[!!!]{RESET} Corrupted JSON format in {data_file_path}.")

    return data

data = load_json_data(data_file_path)

@dataclasses.dataclass()
class Command:
    """
    A dataclass representing a command with its name, command, meta information, and an auto-incrementing ID.

    Attributes
    ----------
    name : str
        The name of the command.
    command : str
        The command to be executed.
    meta : str
        Additional meta information about the command.
    id : int
        The unique ID of the command. It is auto-incremented by default.
    """
    name: str
    command: str
    meta: str
    id: int = dataclasses.field(default_factory=itertools.count().__next__)

# Populate fields with appropriate sub-command class instances
def populate_fields(fields: tuple[str]) -> None:
    """   
    Populates the global data dictionary with Command instances for each field in the provided tuple.

    Parameters
    ----------
    fields : tuple[str]
         A tuple containing the names of the fields to be populated.
    """
    for field in fields:
        for index, cmd in enumerate(data[field]):
            data[field][index] = Command(**cmd)

populate_fields(("reverse", "bind", "msfvenom", "hoaxshell", "listeners"))
logger.debug(f"{CYAN}[*]{RESET} Populated {BOLD}fields{RESET}.")
