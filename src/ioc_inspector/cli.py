import argparse
from pathlib import Path

from .engine import analyze, analyze_many
from .reporter import write_csv, write_json


def _print_table(results) -> None:
    print("\nIOC INSPECTOR")
    print("─" * 88)
    if not results:
        print("No indicators detected.")
        return
    print(f"{'TYPE':<10} {'INDICATOR':<45} {'SCORE':>5}  {'SEVERITY':<9} CONF")
    print("─" * 88)
    for item in results:
        print(f"{item.ioc_type.value.upper():<10} {item.value[:45]:<45} {item.score:>5}  {item.severity.value.upper():<9} {item.confidence}%")
    print("─" * 88)
    print(f"{len(results)} indicator(s) detected")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IOC Inspector — offline-first IOC extraction and risk analysis"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Raw text containing indicators")
    source.add_argument("--file", help="Single text file to analyze")
    source.add_argument("--directory", help="Analyze all .txt/.log files recursively")
    parser.add_argument("--json", dest="json_path", help="Write JSON report")
    parser.add_argument("--csv", dest="csv_path", help="Write CSV report")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal table")
    args = parser.parse_args()

    if args.text:
        results = analyze(args.text)
    elif args.file:
        results = analyze(Path(args.file).read_text(encoding="utf-8"))
    else:
        directory = Path(args.directory)
        files = sorted(
            p for p in directory.rglob("*")
            if p.is_file() and p.suffix.lower() in {".txt", ".log"}
        )
        results = analyze_many([p.read_text(encoding="utf-8", errors="ignore") for p in files])
        print(f"Scanned {len(files)} text/log file(s).")

    if not args.quiet:
        _print_table(results)
    if args.json_path:
        write_json(results, args.json_path)
        print(f"JSON report: {args.json_path}")
    if args.csv_path:
        write_csv(results, args.csv_path)
        print(f"CSV report: {args.csv_path}")


if __name__ == "__main__":
    main()
