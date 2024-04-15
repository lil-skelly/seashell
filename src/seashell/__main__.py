from seashell import *
import argparse
import socket

parser = argparse.ArgumentParser(
    description="Seashell is a CLI 'reverse' shell generator utility. Happy hacking!"
)
parser.add_argument(
    "--verbose",
    "-V",
    help="Sets logging level to [DEBUG]",
    action="store_true"
)

parser.add_argument(
    "-os",
    help="Filters results for [given] operating system",
    type=str,
    choices=["windows", "mac", "linux"]
)

args = parser.parse_args()

def check_interface(i: str) -> str:
    """Validate interface name"""
    try:
        socket.inet_aton(i)
    except socket.error:
        try:
            i = socket.gethostbyname(i)
        except socket.gaierror:
            logging.error(
                f"Error determining HTTP hosting address. Did you provide an interface or IP?")
            return None
    return i

def handle_prompt_validation(prompts: list[dict]) -> list:
    results = []
    for prompt in prompts:
        while True:
            value = input(prompt["text"]).strip()
            value = value if value else prompt["default"]
            if prompt["check"](value):
                results.append(value)
                break
            logger.error(f"{RED}Invalid input. Please provide valid data.{RESET}")
    return results

def get_addr() -> tuple[str, int]:
    address = handle_prompt_validation(
        [
            {
                "text":f"{BOLD}~>{RESET} Enter the {BOLD}{RED}IP{RESET} {CYAN}{BOLD}(default: localhost){RESET}: ",
                "default": "localhost",
                "check": lambda x: check_interface(x)
            },
            {
                "text": f"{BOLD}~>{RESET} Specify the port {CYAN}{BOLD}(default: 4444){RESET}: ",
                "default": 4444,
                "check": lambda x: str(x).isdigit()
            }
        ]
    )
    return address

def get_payload() -> str:
    payload = handle_prompt_validation(
        [
            {
                "text":f"{BOLD}~>{RESET} Select payload type {CYAN}{BOLD}[REVERSE, bind, msfvenom, hoaxshell]{RESET}: ",
                "default": "reverse",
                "check": lambda x: x in ["reverse", "bind", "msfvenom", "hoaxshell"]
            }
        ]
    )

def main(args) -> None:
    if args.verbose:
        logger.setLevel("DEBUG")
        logger.debug(f"{GREEN}[D]{RESET} Enabled {BOLD}verbose mode{RESET} ++")

    if args.os:
        logger.info(f"{BOLD}{CYAN}[*]{RESET} (Filtering results for OS: {args.os})")
        logger.info(f"{CYAN}[*]{RESET} Welcome to the {GREEN}{BOLD}sea of shells{RESET}! Happy pwning >:){RESET}")
    # Get listener address
    addr = get_addr()
    # Select payload type
    payload_type = get_payload()
if __name__ == "__main__":
    main(args)