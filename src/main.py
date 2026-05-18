from pathlib import Path
import argparse
import os
import pandas as pd

from llm_client import LocalLLMClient, LocalLLMError
from workflows.hybrid_workflow import (
    build_workflow,
    clamp_workers,
    evaluate_reports,
    format_evaluation_report,
    print_summary,
    run_batch,
    run_pilot,
    write_evaluation_artifacts,
)


def load_dataset() -> pd.DataFrame:
    project_root = Path(__file__).resolve().parent.parent
    data_path = project_root / "data" / "threat_intel_dataset.jsonl"

    return pd.read_json(data_path, lines=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the hybrid local-LLM cybersecurity threat intelligence workflow."
    )
    parser.add_argument("--row", type=int, default=0, help="Dataset row to analyse in single-record mode.")
    parser.add_argument("--pilot", action="store_true", help="Compare baseline vs hybrid results.")
    parser.add_argument("--batch", action="store_true", help="Generate hybrid reports for multiple rows.")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate an existing report JSONL file.")
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print raw JSON metrics for --evaluate instead of the original-style report.",
    )
    parser.add_argument(
        "--reports",
        type=Path,
        default=None,
        help="Report JSONL file to evaluate. Defaults to outputs/threat_reports.jsonl.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Limit rows for pilot or batch mode.")
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("MAX_CONCURRENT_LLM_REQUESTS", "4")),
        help="Concurrent local LLM requests, capped at 4.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    output_dir = project_root / "outputs"
    df = load_dataset()
    workers = clamp_workers(args.workers)

    if args.evaluate:
        report_path = args.reports or output_dir / "threat_reports.jsonl"
        if not report_path.exists():
            raise SystemExit(f"Report file not found: {report_path}")
        if args.json_summary:
            print_summary(evaluate_reports(df, report_path))
        else:
            report_text = format_evaluation_report(df, report_path)
            paths = write_evaluation_artifacts(report_text, output_dir)
            print(report_text)
            print()
            print(f"Saved text report: {paths['text']}")
            print(f"Saved HTML report: {paths['html']}")
        return

    llm_client = LocalLLMClient()
    try:
        llm_client.ensure_available()
    except LocalLLMError as exc:
        raise SystemExit(str(exc)) from exc

    workflow = build_workflow(llm_client)

    if args.pilot:
        limit = args.limit or 50
        summary = run_pilot(
            df=df,
            workflow=workflow,
            limit=limit,
            workers=workers,
            output_dir=output_dir,
        )
        print_summary(summary)
        return

    if args.batch:
        summary = run_batch(
            df=df,
            workflow=workflow,
            workers=workers,
            output_path=output_dir / "threat_reports.jsonl",
            limit=args.limit,
        )
        print_summary(summary)
        return

    row_index = args.row
    if row_index < 0 or row_index >= len(df):
        raise SystemExit(f"Row index {row_index} is out of range. Dataset has {len(df)} rows.")

    report = workflow.format_report(df.loc[row_index, "input"])
    print(report)

if __name__ == '__main__':
    main()
