import argparse

from .engine import analyze


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC Inspector — offline IOC analysis")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Raw text containing indicators")
    source.add_argument("--file", help="Path to a text file containing indicators")
    args = parser.parse_args()

    text = args.text
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            text = handle.read()

    results = analyze(text or "")
    print("\nIOC INSPECTOR")
    print("─" * 72)
    if not results:
        print("No indicators detected.")
        return

    print(f"{'TYPE':<10} {'INDICATOR':<42} {'SCORE':>5}  SEVERITY")
    print("─" * 72)
    for item in results:
        print(f"{item.ioc_type.value.upper():<10} {item.value[:42]:<42} {item.score:>5}  {item.severity.value.upper()}")
    print("─" * 72)
    print(f"{len(results)} indicator(s) detected")


if __name__ == "__main__":
    main()
