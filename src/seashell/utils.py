import seashell
import socket
import difflib
import re
from . import encoders


def check_interface(i: str) -> str:
    """Validate interface name"""
    try:
        socket.inet_aton(i)
    except socket.error:
        try:
            i = socket.gethostbyname(i)
        except socket.gaierror:
            seashell.logger.error(
                f"Error determining HTTP hosting address. Did you provide an interface or IP?"
            )
            return None
    return i


def list_payloads() -> None:
    """List all the payloads in `seashell.FILTERED_DATA` (handles list command)"""
    for cmd in seashell.FILTERED_DATA.values():
        seashell.logger.info(
            f"{seashell.CYAN}{seashell.BOLD}[*]{seashell.RESET} {cmd.name:<20} {cmd.id}"
        )


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
            seashell.logger.error(
                f"{seashell.RED}Invalid input. Please provide valid data.{seashell.RESET}"
            )
    return results


def filter_results() -> None:
    """Filter the dictionary of payloads for a specific OS and payload type."""
    seashell.logger.debug(
        f"{seashell.GREEN}{seashell.BOLD}[D]{seashell.RESET} Filtering results (OS: {seashell.GREEN}{seashell.BOLD}{seashell.USING_OS}{seashell.RESET}, TYPE: {seashell.GREEN}{seashell.BOLD}{seashell.PAYLOAD_TYPE} shell{seashell.RESET})"
    )
    seashell.FILTERED_DATA = {
        cmd.id: cmd
        for cmd in filter(
            lambda x: seashell.USING_OS in x.meta, seashell.data[seashell.PAYLOAD_TYPE]
        )
    }

    if not seashell.FILTERED_DATA:
        seashell.logger.error(
            f"{seashell.RED}{seashell.BOLD}[!] Could not find any payloads. {seashell.RESET}"
        )
    seashell.logger.debug(f"{seashell.GREEN}[D]{seashell.RESET} Done.")


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
        List of possible matches sorted by similarity score in ascending order
    """
    matches = [
        match
        for token in keyword.split()
        for match in difflib.get_close_matches(token, keys, cutoff=0.4, n=10)
    ]
    if not matches:
        seashell.logger.error(
            f"{seashell.RED}{seashell.BOLD}[!]{seashell.RESET} Could not find any payloads."
        )
        return None

    for _match in matches:
        cmd_iter = filter(
            lambda cmd: cmd.name == keys[_match], seashell.FILTERED_DATA.values()
        )
        cmd = next(cmd_iter)
        seashell.logger.info(
            f"{seashell.CYAN}{seashell.BOLD}[*]{seashell.RESET} {cmd.name:<20} {seashell.GREEN}{seashell.BOLD}{cmd.id}{seashell.RESET}"
        )

    return matches


def handle_interactive():
    """Handles the whole interactive mode"""
    prompts = {
        "ip": {
            "text": f"{seashell.BOLD}~>{seashell.RESET} Enter the {seashell.BOLD}{seashell.RED}IP{seashell.RESET}: ",
            "default": " ",
            "check": lambda x: check_interface(x),
        },
        "port": {
            "text": f"{seashell.BOLD}~>{seashell.RESET} Specify the port {seashell.CYAN}{seashell.BOLD}(default: 4444){seashell.RESET}: ",
            "default": 4444,
            "check": lambda x: str(x).isdigit(),
        },
        "payload_type": {
            "text": f"{seashell.BOLD}~>{seashell.RESET} Select payload type {seashell.CYAN}{seashell.BOLD}[REVERSE, bind, msfvenom, hoaxshell]{seashell.RESET}: ",
            "default": "reverse",
            "check": lambda x: x in ["reverse", "bind", "msfvenom", "hoaxshell"],
        },
        "os": {
            "text": f"{seashell.BOLD}~>{seashell.RESET} Filter by {seashell.BOLD}OS{seashell.RESET} {seashell.CYAN}{seashell.BOLD}[LINUX, mac, windows]{seashell.RESET}: ",
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
    interactive_loop()


def interactive_loop():
    """Contains the interactive query loop for the interactive mode"""
    processed_keys = {
        command.name.lower(): command.name
        for command in seashell.FILTERED_DATA.values()
    }
    while True:
        keyword = input(f"{seashell.BOLD}[SEARCH]{seashell.RESET} ").lower()
        if not keyword:
            seashell.logger.warning(
                f"{seashell.RED}{seashell.BOLD} Provide a valid search query{seashell.RESET}"
            )
            continue
        # set payload (use X)
        if re.match(r"^use \d+$", keyword):
            id_ = int(keyword.split(" ")[1])
            if not set_payload_from_id(id_):
                continue
        elif keyword == "list":
            list_payloads()
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
        Returns False if `PAYLOAD` is not set, else True
    """
    try:
        seashell.PAYLOAD = seashell.FILTERED_DATA.get(id_)
        seashell.logger.info(
            f"{seashell.GREEN}{seashell.BOLD}[+]{seashell.RESET} Using <{seashell.BOLD}{seashell.PAYLOAD.name}{seashell.RESET}>"
        )
    except KeyError:
        seashell.logger.error(
            f"{seashell.RED}{seashell.BOLD}[!]{seashell.RESET} Could not find payload with ID {id_}"
        )
        return False

    return True


def substitute_payload(payload: seashell.Command, args) -> None:
    """Substitute the given `payload.command` with the values specified in the substitutions map.

    Parameters
    ----------
    payload : Command
        Command class to modify
    args : _type_
        Parsed command-line arguments to substitute
    """
    substitutions = {
        "{ip}": seashell.ADDRESS[0],
        "{port}": str(seashell.ADDRESS[1]),
        "{payload}": args.payload,
        "{shell}": args.shell,
    }

    for placeholder, value in substitutions.items():
        payload.command = payload.command.replace(placeholder, value)


def finalize_payload(payload: seashell.Command, args) -> None:
    """
    Finalizes and outputs the payload or writes to file if specified in a command-line argument.

    This function takes a payload command and command-line arguments as input. It first substitutes
    placeholders in the payload command with actual values based on the provided arguments. Then,
    if an encoder is selected, it encrypts the payload command using the specified encoder and
    the given number of iterations.

    Parameters
    ----------
    payload : seashell.Command
        The command instance to modify.
    args : _type_
        Parsed command-line arguments containing required information.
    """
    substitute_payload(payload, args)

    if seashell.ENCODER:
        handle_payload_encoding(payload, args.iterations)


def handle_payload_output(args) -> None:
    """
    Finalize and output the payload or write to file if specified in a command-line argument

    Parameters
    ----------
    args : _type_
        Parsed command-line arguments
    """
    finalize_payload(seashell.PAYLOAD, args)

    if args.output:
        save_payload_to_file()
    else:
        seashell.logger.info(
            f"{seashell.GREEN}{seashell.BOLD}[+]{seashell.RESET} {seashell.PAYLOAD.name} | {seashell.BOLD}IP{seashell.RESET}: {seashell.GREEN}{seashell.BOLD}{seashell.ADDRESS[0]}{seashell.RESET} {seashell.BOLD}PORT{seashell.RESET}: {seashell.GREEN}{seashell.BOLD}{seashell.ADDRESS[1]}{seashell.RESET}\n{seashell.PAYLOAD.command}"
        )


def save_payload_to_file() -> None:
    """
    Saves the payload command to a file.

    If `seashell.OUTPUT_PATH` is provided, the payload command is written to that file.
    If not, the payload command is written to a file named "payload.txt".

    Raises:
    -------
    OSError: If there is an error opening or writing to the file.
    """
    path = seashell.OUTPUT_PATH if seashell.OUTPUT_PATH else "payload.txt"
    try:
        with open(path, "w") as fd:
            fd.write(seashell.PAYLOAD.command)
    except OSError as e:
        seashell.logger.error(f"{seashell.RED}{seashell.BOLD}[!]{seashell.RESET} {e}")


def handle_payload_encoding(payload: seashell.Command, iterations: int) -> None:
    """Encodes given data using the selected encoder with the given iterations"""
    payload.command = encoders.ENCODER_MAP[seashell.ENCODER]().encode(payload.command.encode(), iterations).decode()
