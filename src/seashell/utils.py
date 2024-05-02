from seashell import *
import seashell
import socket
import difflib
import re

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
    """Automates the process of validating user input

    Parameters
    ----------
    prompts : list[dict]
        List of dictionaries which contain the prompt for the user, the type of the value to be stored and a lambda function for the validation

    Returns
    -------
    list
        List containing the answers from the prompts
    """
    results = {}
    for key, prompt in prompts.items():
        while True:
            value = input(prompt["text"]).strip()
            value = value if value else prompt["default"]
            if prompt["check"](value):
                results[key] = value
                break
            logger.error(f"{RED}Invalid input. Please provide valid data.{RESET}")
    return results

def filter_results() -> None:
    """Filter the dictionary of payloads for a specific OS and payload type."""
    logger.debug(
        f"{GREEN}{BOLD}[D]{RESET} Filtering results (OS: {GREEN}{BOLD}{seashell.USING_OS}{RESET}, TYPE: {GREEN}{BOLD}{seashell.PAYLOAD_TYPE} shell{RESET})"
    )
    seashell.FILTERED_DATA = {
        cmd.id: cmd
        for cmd in filter(
            lambda x: seashell.USING_OS in x.meta, data[seashell.PAYLOAD_TYPE]
        )
    }

    if not seashell.FILTERED_DATA:
        logger.error(f"{RED}{BOLD}[!] Could not find any payloads. {RESET}")
    logger.debug(f"{GREEN}[D]{RESET} Done.")

def get_payload_matches(keyword: str, keys: dict[str, str]) -> list[str] | None:
    """Gets possible matches in `keys` using `keyword`

    Parameters
    ----------
    keyword : str
        Keyword to search
    keys : dict[str, str]
        Keys directory to search payloads

    Returns
    -------
    list[str] | None
        _description_
    """
    matches = [
        match
        for token in keyword.split()
        for match in difflib.get_close_matches(token, keys, cutoff=0.4, n=10)
    ]
    if not matches:
        logger.error(f"{RED}{BOLD}[!]{RESET} Could not find any payloads.")
        return None
    
    for _match in matches:
        cmd_iter = filter(
            lambda cmd: cmd.name == keys[_match], seashell.FILTERED_DATA.values()
        )
        cmd = next(cmd_iter)
        logger.info(
            f"{CYAN}{BOLD}[*]{RESET} {cmd.name:<20} {GREEN}{BOLD}{cmd.id}{RESET}"
        )
    
    return matches


def handle_interactive():
    """Handles the whole interactive mode"""
    prompts = {
        "ip": {
            "text": f"{BOLD}~>{RESET} Enter the {BOLD}{RED}IP{RESET}: ",
            "default": " ",
            "check": lambda x: check_interface(x),
        },
        "port": {
            "text": f"{BOLD}~>{RESET} Specify the port {CYAN}{BOLD}(default: 4444){RESET}: ",
            "default": 4444,
            "check": lambda x: str(x).isdigit(),
        },
        "payload_type": {
            "text": f"{BOLD}~>{RESET} Select payload type {CYAN}{BOLD}[REVERSE, bind, msfvenom, hoaxshell]{RESET}: ",
            "default": "reverse",
            "check": lambda x: x in ["reverse", "bind", "msfvenom", "hoaxshell"],
        },
        "os": {
            "text": f"{BOLD}~>{RESET} Filter by {BOLD}OS{RESET} {CYAN}{BOLD}[LINUX, mac, windows]{RESET}: ",
            "default": "linux",
            "check": lambda x: x in ["windows", "linux", "mac"],
        },
    }
    # Get listener address
    results = handle_prompt_validation(prompts)

    seashell.ADDRESS = check_interface(results["ip"]), results["port"]
    # Select payload type
    seashell.USING_OS = results["os"]
    seashell.PAYLOAD_TYPE = results["payload_type"]

    filter_results()
    processed_keys = {command.name.lower(): command.name for command in seashell.FILTERED_DATA.values()}
    
    while True:
        keyword = input(f"{BOLD}[SEARCH]{RESET} ").lower()
        if not keyword:
            logger.warning(f"{RED}{BOLD} Provide a valid search query{RESET}")
            continue
        # set payload (use X) 
        if re.match(r"^use \d+$", keyword):
            id_ = int(keyword.split(" ")[1])
            if not set_payload_from_id(id_):
                continue
        elif keyword == "list":
            for cmd in seashell.FILTERED_DATA.values():
                logger.info(
                    f"{CYAN}{BOLD}[*]{RESET} {cmd.name:<20} {cmd.id}")
        # search for payload
        else:
            matches = get_payload_matches(keyword, processed_keys)
            if not matches:
                continue
        if seashell.PAYLOAD:
            break

def set_payload_from_id(id_: int) -> bool:
    """Assistance function used to encapsulate the searching logic and remove duplicated code throughout the file.

    Parameters
    ----------
    keyword : str
        Keyword from which to extract payload ID

    Returns
    -------
    bool
        Returns False if `seashell.PAYLOAD` is not set, else True
    """
    try:
        seashell.PAYLOAD = seashell.FILTERED_DATA.get(id_)
        logger.info(
            f"{GREEN}{BOLD}[+]{RESET} Using <{BOLD}{seashell.PAYLOAD.name}{RESET}>"
        )
    except KeyError:
        logger.error(f"{RED}{BOLD}[!]{RESET} Could not find payload with ID {id_}")
        return False
    
    return True

def substitute_payload(payload: Command, args) -> Command:
    """Substitute the given `payload.command` with the values specified in the substitutions map.

    Parameters
    ----------
    payload : Command
        Command class to modify
    args : _type_
        Parsed command-line arguments to substitute

    Returns
    -------
    Command
        Modified Command instance containing substituted payload.
    """
    substitutions = {
        "{ip}": seashell.ADDRESS[0],
        "{port}": str(seashell.ADDRESS[1]),
        "{payload}": args.payload,
        "{shell}": args.shell
    }

    for placeholder, value in substitutions.items():
        payload.command = payload.command.replace(placeholder, value)

    return payload

def handle_payload_output(args): 
    """Output the final payload or write to file if specified as a command-line argument

    Parameters
    ----------
    args : _type_
        Parsed command-line arguments
    """
    substitute_payload(seashell.PAYLOAD, args)
    if args.output:
        with open(args.output, "w") as fd:
            fd.write(seashell.PAYLOAD.command)
            logger.info(f"{GREEN}{BOLD}[+]{RESET} Wrote payload to <{BOLD}{args.output}{RESET}>")
    else:
        logger.info(
            f"{GREEN}{BOLD}[+]{RESET} {seashell.PAYLOAD.name} | {BOLD}IP{RESET}: {GREEN}{BOLD}{seashell.ADDRESS[0]}{RESET} {BOLD}PORT{RESET}: {GREEN}{BOLD}{seashell.ADDRESS[1]}{RESET}"
            + f"\n{seashell.PAYLOAD.command}"
        )
