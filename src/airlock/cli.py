"""
© https://github.com/YouFoundTheDev | 2026
cli.py
"""

import argparse
import sys
from collections.abc import Sequence

from airlock import __version__
from airlock.capability import Reply
from airlock.contract import Contract
from airlock.engine import Engine
from airlock.envelope import Envelope, Provenance, Source
from airlock.ruling import Outcome, Ruling
from airlock.settings import CLI, RULE_MUTED


def _read(text: str | None) -> str:
    if text is not None:
        return text
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def _envelope(text: str, provenance: str) -> Envelope:
    envelope = Envelope()

    if provenance == Provenance.INSTRUCTION:
        return envelope.instruction(text)
    if provenance == Provenance.REQUEST:
        return envelope.request(text)

    return envelope.content(
        text,
        source = Source(
            channel = CLI.default_channel,
            ref = CLI.default_ref,
        ),
    )


def _report(outcome: Outcome) -> None:
    print(
        CLI.ruling_line.format(
            ruling = str(outcome.ruling).upper(),
            took = outcome.took_ms,
            contract = outcome.contract_id,
        )
    )

    fired = [alert for alert in outcome.alerts if alert.rule != RULE_MUTED]
    if not fired:
        print(CLI.quiet)
        return

    for alert in fired:
        print(
            CLI.alert_line.format(
                mark = CLI.hard_mark if alert.hard else CLI.soft_mark,
                check = alert.check,
                rule = alert.rule,
                weight = alert.weight.name,
            )
        )


def _status(outcome: Outcome) -> int:
    return 1 if outcome.ruling is Ruling.REFUSE else 0


def _scan(args: argparse.Namespace) -> int:
    text = _read(args.text)
    if not text:
        print(CLI.empty_input, file = sys.stderr)
        return 2

    engine = Engine(Contract(strict = not args.lenient))
    outcome = engine.inspect(_envelope(text, args.provenance))

    _report(outcome)
    if args.provenance == CLI.default_provenance:
        print(CLI.phrasing_caveat, file = sys.stderr)
    return _status(outcome)


def _release(args: argparse.Namespace) -> int:
    text = _read(args.text)
    if not text:
        print(CLI.empty_input, file = sys.stderr)
        return 2

    engine = Engine(
        Contract(
            secrets = tuple(args.secret),
            hosts = tuple(args.allow_host),
        )
    )
    outcome = engine.authorize(
        Reply(body = text),
        Envelope().request(""),
    )

    _report(outcome)
    return _status(outcome)


def _bench(args: argparse.Namespace) -> int:
    try:
        from bench.runner import format_report, run, run_ablation
    except ImportError:
        print(CLI.bench_unavailable, file = sys.stderr)
        return 2

    print(format_report(run(), run_ablation()))
    return 0


def _serve(factory: str, host: str, port: int) -> int:
    import uvicorn

    uvicorn.run(factory, factory = True, host = host, port = port)
    return 0


def _proxy(args: argparse.Namespace) -> int:
    return _serve("airlock.server.chat:build_app", args.host, args.port)


def _arena(args: argparse.Namespace) -> int:
    return _serve("airlock.server.arena:build_arena", args.host, args.port)


def _text_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "text",
        nargs = "?",
        default = None,
        help = "text to inspect; reads stdin when omitted",
    )


def _serve_command(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    port: int,
    run: object,
) -> None:
    parser = sub.add_parser(name, help = help_text)
    parser.add_argument("--host", default = CLI.default_host)
    parser.add_argument("--port", type = int, default = port)
    parser.set_defaults(run = run)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the argument parser, which is also the only place the
    command surface is described
    """
    parser = argparse.ArgumentParser(
        prog = CLI.program,
        description = CLI.description,
        epilog = CLI.epilog,
    )
    parser.add_argument(
        "--version",
        action = "version",
        version = f"{CLI.program} {__version__}",
    )
    sub = parser.add_subparsers(dest = "command", required = True)

    scan = sub.add_parser(
        "scan",
        help = "inspect text on the way in to a model",
    )
    _text_argument(scan)
    scan.add_argument(
        "--provenance",
        choices = CLI.provenance_choices,
        default = CLI.default_provenance,
        help = "where the text came from; this decides the outcome",
    )
    scan.add_argument(
        "--lenient",
        action = "store_true",
        help = "score instruction-shaped prose instead of refusing it",
    )
    scan.set_defaults(run = _scan)

    release = sub.add_parser(
        "release",
        help = "inspect model output on the way out",
    )
    _text_argument(release)
    release.add_argument(
        "--secret",
        action = "append",
        default = [],
        help = "a value that must not leave, in any encoding",
    )
    release.add_argument(
        "--allow-host",
        action = "append",
        default = [],
        help = "permitted host; a leading dot covers subdomains",
    )
    release.set_defaults(run = _release)

    bench = sub.add_parser(
        "bench",
        help = "run the benchmark and the per-check ablation",
    )
    bench.set_defaults(run = _bench)

    serve = sub.add_parser("serve", help = "run one of the HTTP servers")
    serving = serve.add_subparsers(dest = "server", required = True)
    _serve_command(
        serving,
        "proxy",
        "serve the [OI]-compatible proxy",
        CLI.proxy_port,
        _proxy,
    )
    _serve_command(
        serving,
        "arena",
        "serve the arena",
        CLI.arena_port,
        _arena,
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """
    Entry point, returning the exit status rather than raising
    """
    args = build_parser().parse_args(argv)
    status: int = args.run(args)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
