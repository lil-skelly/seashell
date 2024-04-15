from seashell import *
import argparse

parser = argparse.ArgumentParser(
    description="Seashell is a CLI 'reverse' shell generator utility. Happy hacking!"
)
parser.add_argument(
    "--verbose",
    "-V",
    help="Sets logging level to [DEBUG]",
    type=bool
)

args = parser.parse_args()

if args.verbose:
    logger.setLevel("DEBUG")
    logger.debug(f"{GREEN}[D]{RESET} Enabled {BOLD}verbose mode{RESET} ++")
