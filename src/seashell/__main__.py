import seashell
import seashell.utils as utils
import seashell.encoders as encoders
import argparse
import re

parser = argparse.ArgumentParser(
    prog="python3 -m seashell",
    description="Seashell is a CLI 'reverse' shell generator utility. Happy hacking!",
)

parser.add_argument(
    "--verbose",
    "-V",
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
    choices=seashell.data["shells"],
    default="bash",
)

parser.add_argument(
    "-P",
    "--payload",
    help="metasploit payload to use for listener [msfconsole]",
    type=str,
    default="windows/x64/meterpreter/reverse_tcp",
)

parser.add_argument(
    "--interactive",
    "-i",
    help="Enables interactive mode. Any arguments besides -V will be ignored!",
    action="store_true",
)

parser.add_argument("--output", "-O", type=str, help="Store payload to file")

parser.add_argument(
    "--encoder",
    "-e",
    type=str,
    choices=tuple(encoders.ENCODER_MAP.keys()),
    help="The encoder to use",
)

parser.add_argument(
    "--iterations",
    "-I",
    type=int,
    choices=(1, 2, 3, 4, 5),
    default=1,
    help="The number of times to encode the payload",
)

parser.add_argument(
    "term",
    nargs="?",
    help="Search term to filter payloads (use list to list payloads).",
    type=str,
)

args = parser.parse_args()

def configure_logger(args):
    seashell.logger.info(
        f"{seashell.GREEN}{seashell.BOLD}[+]{seashell.RESET} Welcome to the {seashell.GREEN}{seashell.BOLD}sea of shells{seashell.RESET}! Happy pwning >:){seashell.RESET}"
    )
    if args.verbose:
        seashell.logger.setLevel("DEBUG")
        seashell.logger.debug(f"{seashell.GREEN}[D]{seashell.RESET} Enabled {seashell.BOLD}verbose mode{seashell.RESET} ++")

def handle_payload_search(args):
    if args.term:
        if re.match(r"\d+$", args.term):
            id_ = int(args.term)
            if not utils.set_payload_from_id(id_):
                exit()
        elif args.term == "list":
            utils.list_payloads()
        else:
            processed_keys = {
                command.name.lower(): command.name
                for command in seashell.FILTERED_DATA.values()
            }
            matches = utils.get_payload_matches(
                args.term.strip(), processed_keys
            )
            if not matches:
                exit()

def main(args) -> None:
    try:
        configure_logger(args)
        if args.output:
            seashell.OUTPUT_FILE = args.output
            seashell.logger.debug(f"{seashell.GREEN}[D]{seashell.RESET} Storing payload to file {seashell.BOLD}{args.output}{seashell.RESET}")
        if args.encoder:
            seashell.ENCODER = args.encoder
            seashell.logger.debug(f"{seashell.GREEN}[D]{seashell.RESET} Using encoder {seashell.BOLD}{args.encoder}{seashell.RESET}")
        if args.interactive:
            utils.handle_interactive()
        else:  # Manual mode
            # Prepare key variables
            seashell.USING_OS = args.os
            seashell.PAYLOAD_TYPE = args.type

            seashell.ADDRESS[1] = args.port
            if not args.ip:
                seashell.logger.error(f"{seashell.RED}{seashell.BOLD}[!]{seashell.RESET} Missing target IP. Exiting.")
                exit(1)
            else:
                ip = utils.check_interface(args.ip)
                if not ip:
                    exit(1)
                seashell.ADDRESS[0] = ip

            # Start filtering data
            utils.filter_results()
            handle_payload_search(args)

        # Final step (output payload)
        if seashell.PAYLOAD:
            utils.handle_payload_output(args)

    except KeyboardInterrupt:
        seashell.logger.error(f"{seashell.RED}{seashell.BOLD}[!] Received keyboard interrupt.")


if __name__ == "__main__":
    main(args)