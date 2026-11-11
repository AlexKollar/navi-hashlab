"""Navi Hashlab — entry point for the Apex chip runner.

The whole lab lives in the app_hashlab package beside this file;
this entry only adapts Apex's run(args) call to it. Apex passes the
words after the chip name as args.text, e.g.:

    id 5f4dcc3b5aa765d61d8327deb882cf99
"""

try:
    from app_hashlab.core import parse_and_run
except ImportError:  # package-mode runner: the package rides beside us
    try:
        from .app_hashlab.core import parse_and_run
    except ImportError:
        parse_and_run = None


def run(args):
    if parse_and_run is None:
        print("error: the app_hashlab package did not load with this chip.")
        return
    text = (getattr(args, "text", "") or "").strip()
    parse_and_run(text)
