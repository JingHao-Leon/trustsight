import logging
import os
import sys

import typer


def _version_callback(value: bool):
    if value:
        from .. import __version__
        typer.echo(f"trustsight {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="trustsight",
    help="TrustSight - AUR Package Update Vetting Tool",
    no_args_is_help=True,
    add_completion=True,
    epilog="New? Start with 'trustsight review', then 'trustsight inspect <pkg>'.",
)


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "-v", "--version",
        callback=_version_callback,
        help="Show program's version number and exit",
    ),
):
    # Every command warns when a newer release exists, so a version behind
    # cannot silently miss a detection.  Skipped for `--help`/`-h` (help
    # must not touch the network or create config) and for `-v`/`--version`
    # (handled eagerly above).
    argv = sys.argv[1:]
    if not any(token in argv for token in ("-h", "--help", "-v", "--version")):
        from .updates import check_and_warn

        check_and_warn()


# Register all command modules
from .review import register_commands as _register_review
from .inspect import register_commands as _register_inspect
from .explain import register_commands as _register_explain
from .lint import register_commands as _register_lint
from .history import register_commands as _register_history
from .list_cmd import register_commands as _register_list
from .forget import register_commands as _register_forget
from .admin import register_commands as _register_admin
from .corpus import register_commands as _register_corpus
from .ioc import register_commands as _register_ioc
from .seed import register_commands as _register_seed

_register_review(app)
_register_inspect(app)
_register_explain(app)
_register_lint(app)
_register_history(app)
_register_list(app)
_register_forget(app)
_register_admin(app)
_register_corpus(app)
_register_ioc(app)
_register_seed(app)


def main() -> None:
    """Console entry point.

    Uncaught exceptions become exit code 2 (operational failure), matching the
    contract in docs/reference/exit-codes.md: 0 means the command ran, 2 means
    it could not run or complete. Deliberate exits (typer.Exit) pass through.
    """
    # The corpus pipeline reports progress through logging; without a
    # handler those messages (including its refusal to bootstrap) would be
    # invisible.  Messages go to stderr so stdout stays machine-readable.
    #
    # `TRUSTSIGHT_LOG_LEVEL` raises or lowers the level, and
    # `TRUSTSIGHT_LOG_TIMESTAMPS` adds a timestamp and level to each line, so
    # an unattended watcher's `docker logs` (or journal) shows *when* a cycle
    # ran.  `force=True` replaces any handler a library installed first.
    level = getattr(logging, os.environ.get("TRUSTSIGHT_LOG_LEVEL", "").upper(),
                    logging.INFO)
    fmt = ("%(asctime)s %(levelname)s %(message)s"
           if os.environ.get("TRUSTSIGHT_LOG_TIMESTAMPS", "").strip()
           else "%(message)s")
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr, force=True)
    try:
        app()
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise typer.Exit(code=130)
    except Exception as exc:
        print(f"trustsight: error: {exc}", file=sys.stderr)
        raise typer.Exit(code=2)
