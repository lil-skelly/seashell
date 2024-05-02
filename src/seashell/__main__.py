from seashell import *
import seashell
import seashell.utils as utils
import argparse
import socket
import difflib, re

parser = argparse.ArgumentParser(
    prog="python3 -m seashell",
    description="Seashell is a CLI 'reverse' shell generator utility. Happy hacking!",
)

parser.add_argument(
    "--verbose", "-V", 
    "-v",
    help="Sets logging level to [DEBUG]", 
    action="store_true",
)

parser.add_argument(
    "-os",
    "-o",
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
    "--type",
    "-T",
    help="Filters results for [given] payload type ",
    type=str,
    choices=["reverse", "bind", "msfvenom", "hoaxshell", "listeners"],
    default="reverse",
)

parser.add_argument(
    "--shell",
    "-S",
    help="Shell to use",
    type=str,
    choices=data["shells"],
    default="bash",
)

parser.add_argument(
    "-P",
    "--payload",
    help="metasploit payload to use for listener [msfconsole]",
    type=str,
    default="windows/x64/meterpreter/reverse_tcp"
)

parser.add_argument(
    "--interactive",
    "-i",
    help="Enables interactive mode. Any arguments besides -V will be ignored!",
    action="store_true",
)
parser.add_argument(
    "--output",
    "-O",
    type=str,
    help="Store payload to file"
)

parser.add_argument("term", nargs="?", help="Search term to filter payloads (use list to list payloads).", type=str)

args = parser.parse_args()


def main(args) -> None:
    try:
        logger.info(
            f"{GREEN}{BOLD}[+]{RESET} Welcome to the {GREEN}{BOLD}sea of shells{RESET}! Happy pwning >:){RESET}"
        )
        if args.verbose:
            logger.setLevel("DEBUG")
            logger.debug(f"{GREEN}[D]{RESET} Enabled {BOLD}verbose mode{RESET} ++")

        if args.interactive:
            utils.handle_interactive()
        else: # Manual mode
            # Prepare key variables
            seashell.USING_OS = args.os
            seashell.PAYLOAD_TYPE = args.type

            seashell.ADDRESS[1] = args.port
            if not args.ip:
                logger.error(f"{RED}{BOLD}[!]{RESET} Missing target IP. Exiting.")
                exit(1)
            else:
                ip = utils.check_interface(args.ip)
                if not ip: exit(1)
                seashell.ADDRESS[0] = ip

            # Start filtering data 
            utils.filter_results()
            if args.term:  
                if re.match(r"\d+$", args.term):
                    id_ = int(args.term)
                    if not utils.set_payload_from_id(id_):
                        exit()
                elif args.term == "list":
                    for cmd in seashell.FILTERED_DATA.values():
                        logger.info(f"{CYAN}{BOLD}[*]{RESET} {cmd.name:<20} {cmd.id}")
                else:
                    processed_keys = {command.name.lower(): command.name for command in seashell.FILTERED_DATA.values()}
                    # processed_keys = {key.lower(): key for key in seashell.FILTERED_DATA.keys()}
                    matches = utils.get_payload_matches(args.term.strip(), processed_keys)
                    if not matches:
                        exit()

        # Final step (output payload)
        if seashell.PAYLOAD:
            utils.handle_payload_output(args)

    except KeyboardInterrupt:
        logger.error(f"{RED}{BOLD}[!] Received keyboard interrupt.")


if __name__ == "__main__":
    main(args)
