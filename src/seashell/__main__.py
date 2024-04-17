from seashell import *
import seashell
import argparse
import socket
import difflib, re

parser = argparse.ArgumentParser(
    prog="python3 -m seashell",
    description="Seashell is a CLI 'reverse' shell generator utility. Happy hacking!",
)

parser.add_argument(
    "--verbose", "-V", help="Sets logging level to [DEBUG]", action="store_true"
)

parser.add_argument(
    "-os",
    help="Filters results for [given] operating system",
    type=str,
    choices=["windows", "mac", "linux"],
    default="linux",
)

parser.add_argument(
    "-ip",
    help="Target IP",
    type=str,
)

parser.add_argument("-p", "--port", help="Target port", type=int, default=4444)

parser.add_argument(
    "-shell",
    "-S",
    help="Filters results for [given] shell type ",
    type=str,
    choices=["reverse", "bind", "msfvenom", "hoaxshell"],
    default="reverse",
)

parser.add_argument(
    "--interactive",
    "-i",
    help="Enables interactive mode. Any arguments besides -V will be ignored!",
    action="store_true",
)

parser.add_argument("term", nargs="?", help="Search term to filter payloads.", type=str)

args = parser.parse_args()


def check_interface(i: str) -> str:
    """Validate interface name"""
    try:
        socket.inet_aton(i)
    except socket.error:
        try:
            i = socket.gethostbyname(i)
        except socket.gaierror:
            logger.error(
                f"Error determining HTTP hosting address. Did you provide an interface or IP?"
            )
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


def filter_results() -> None:
    logger.debug(
        f"{GREEN}[D]{RESET} Filtering results (OS: {GREEN}{BOLD}{seashell.USING_OS}{RESET}, TYPE: {GREEN}{BOLD}{seashell.PAYLOAD_TYPE} shell{RESET})"
    )
    seashell.FILTERED_DATA = {
        cmd.name: cmd
        for cmd in filter(
            lambda x: seashell.USING_OS in x.meta, data[seashell.PAYLOAD_TYPE]
        )
    }
    if not seashell.FILTERED_DATA:
        logger.error(f"{BOLD}{RED}[!]{RESET} Could not find any payloads.")
    logger.debug(f"{GREEN}[D]{RESET} Done.")


def get_payload_matches(keyword: str, keys: dict[str, str]) -> list[str] | None:
    matches = [
        match
        for token in keyword.lower().split()
        for match in difflib.get_close_matches(token, keys, cutoff=0.4, n=10)
    ]
    if not matches:
        logger.error(f"{RED}{BOLD}[!]{RESET} Could not find any payloads.")
        return None
    
    for _match in matches:
        cmd = seashell.FILTERED_DATA[keys[_match]]
        logger.info(
            f"{CYAN}{BOLD}[*]{RESET} {cmd.name:<20} {GREEN}{BOLD}{cmd.id}{RESET}"
        )
    
    return matches



def handle_interactive():
    prompts = {
        "ip_prompt": {
            "text": f"{BOLD}~>{RESET} Enter the {BOLD}{RED}IP{RESET}: ",
            "default": " ",
            "check": lambda x: check_interface(x),
        },
        "port_prompt": {
            "text": f"{BOLD}~>{RESET} Specify the port {CYAN}{BOLD}(default: 4444){RESET}: ",
            "default": 4444,
            "check": lambda x: str(x).isdigit(),
        },
        "payload_prompt": {
            "text": f"{BOLD}~>{RESET} Select payload type {CYAN}{BOLD}[REVERSE, bind, msfvenom, hoaxshell]{RESET}: ",
            "default": "reverse",
            "check": lambda x: x in ["reverse", "bind", "msfvenom", "hoaxshell"],
        },
        "os_prompt": {
            "text": f"{BOLD}~>{RESET} Filter by {BOLD}OS{RESET} {CYAN}{BOLD}[LINUX, mac, windows]{RESET}: ",
            "default": "linux",
            "check": lambda x: x in ["windows", "linux", "mac"],
        },
        # "search_prompt": {
        #     "text":f"{BOLD}[SEARCH]{RESET} ",
        #     "default":None,
        #     "check": lambda x: x
        # }
    }
    # Get listener address
    seashell.ADDRESS = handle_prompt_validation(
        [prompts["ip_prompt"], prompts["port_prompt"]]
    )[0]
    # Select payload type
    seashell.USING_OS = handle_prompt_validation([prompts["os_prompt"]])[0]
    seashell.PAYLOAD_TYPE = handle_prompt_validation([prompts["payload_prompt"]])[0]

    filter_results()
    
    processed_keys = {key.lower(): key for key in seashell.FILTERED_DATA.keys()}
    while True:
        keyword = input(f"{BOLD}[SEARCH]{RESET} ")
        if not keyword:
            logger.warning(f"{RED}{BOLD} Provide a valid search query{RESET}")
            continue
        # set payload (use X) 
        if re.match(r"^use \d+$", keyword):
            _id = int(keyword.split(" ")[1])
            for cmd in seashell.FILTERED_DATA.values():
                if cmd.id == _id:
                    seashell.PAYLOAD = cmd
                    logger.info(
                        f"{GREEN}{BOLD}[+]{RESET} Using <{BOLD}{cmd.name}{RESET}>"
                    )
                    continue
            if not seashell.PAYLOAD:
                logger.error(f"{RED}{BOLD}[!] Could not find payload with ID {_id}")
                continue
        # search for payload
        else:
            matches = get_payload_matches(keyword, processed_keys)
            if not matches:
                continue
        if seashell.PAYLOAD:
            break


def main(args) -> None:
    try:
        logger.info(
            f"{CYAN}[*]{RESET} Welcome to the {GREEN}{BOLD}sea of shells{RESET}! Happy pwning >:){RESET}"
        )
        if args.verbose:
            logger.setLevel("DEBUG")
            logger.debug(f"{GREEN}[D]{RESET} Enabled {BOLD}verbose mode{RESET} ++")

        if args.interactive:
            handle_interactive()
        else:
            seashell.USING_OS = args.os
            seashell.PAYLOAD_TYPE = args.shell

            seashell.ADDRESS[1] = args.port
            if args.ip:
                ip = check_interface(args.ip)
                if not ip:
                    exit(1)
                seashell.ADDRESS[0] = ip
            else:
                logger.error(f"{BOLD}{RED}[!]{RESET} Missing target IP. Exiting.")
            filter_results()
            if args.term:  
                if re.match(r"\d+$", args.term):
                    _id = int(args.term)
                    for cmd in seashell.FILTERED_DATA.values():
                        if cmd.id == _id:
                            seashell.PAYLOAD = cmd
                            logger.info(
                                f"{GREEN}{BOLD}[+]{RESET} Using <{BOLD}{cmd.name}{RESET}>"
                            )
                            break
                    if not seashell.PAYLOAD:
                        logger.error(f"{RED}{BOLD}[!] Could not find payload with ID {_id}")
                        exit()
                else:
                    processed_keys = {key.lower(): key for key in seashell.FILTERED_DATA.keys()}
                    matches = get_payload_matches(args.term.strip(), processed_keys)
                    if not matches:
                        exit()
             
    except KeyboardInterrupt:
        logger.error(f"{RED}{BOLD}[!] Received keyboard interrupt.")


if __name__ == "__main__":
    main(args)