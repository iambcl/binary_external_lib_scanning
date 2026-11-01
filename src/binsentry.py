import argparse
from pathlib import Path
from scan import scan_binary

def main():
    parser = argparse.ArgumentParser(
        prog="binsentry",
        description="Performs dependency version checking",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("filepath", type=Path)

    args = parser.parse_args()
    results = scan_binary.open_binary(args.filepath)
    print(results)


if __name__ == "__main__":
    main()
