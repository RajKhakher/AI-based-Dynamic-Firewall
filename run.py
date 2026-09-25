#!/usr/bin/env python3
"""
run.py - start the AI-Based Dynamic Firewall System.

This is the single command you run. It starts two things in one process:

  1. The firewall engine (needs root, because it talks to the kernel).
  2. The web dashboard (so you can watch and control it in a browser).

Usage
-----
  sudo python3 run.py                 # engine + dashboard (default)
  sudo python3 run.py --mode enforce  # start already enforcing
  sudo python3 run.py --no-web        # engine only, no dashboard
  python3 run.py --web-only           # dashboard only, no kernel hooks
                                      # (handy for viewing history without root)

Press Ctrl+C to stop. On exit, every kernel rule this program added is removed,
so your machine is left exactly as it was.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

from fwcore import config


def _need_root():
    if os.geteuid() != 0:
        print("This needs root because it installs firewall rules in the kernel.")
        print("Try:  sudo python3 run.py")
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="AI-Based Dynamic Firewall System")
    ap.add_argument("--mode", choices=["monitor", "enforce"], default=None,
                    help="monitor = watch only (default), enforce = actually block")
    ap.add_argument("--no-web", action="store_true", help="run the engine without the dashboard")
    ap.add_argument("--web-only", action="store_true", help="run only the dashboard (no root needed)")
    ap.add_argument("--host", default=None, help="dashboard bind address")
    ap.add_argument("--port", type=int, default=None, help="dashboard port")
    args = ap.parse_args()

    cfg = config.load()
    if args.mode:
        cfg["mode"] = args.mode
        config.save(cfg)
    if args.host:
        cfg["web"]["host"] = args.host
    if args.port:
        cfg["web"]["port"] = args.port

    engine = None
    if not args.web_only:
        _need_root()
        from fwcore.engine import FirewallEngine
        engine = FirewallEngine(cfg)

        def _cleanup(*_):
            print("\nShutting down and removing firewall rules...")
            if engine:
                engine.stop()
            print("Done. Your machine is back to normal.")
            os._exit(0)

        signal.signal(signal.SIGINT, _cleanup)
        signal.signal(signal.SIGTERM, _cleanup)

        print(f"Starting firewall engine in '{engine.mode}' mode...")
        engine.start(background=True)
        print("Engine running. Kernel hooks installed.")

    if args.no_web:
        print("Dashboard disabled (--no-web). Engine running; press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            if engine:
                engine.stop()
        return

    # Start the dashboard (this blocks).
    from web.server import create_app
    app = create_app(engine)
    host = cfg["web"]["host"]
    port = cfg["web"]["port"]
    print(f"Dashboard at http://{host}:{port}   (default login: admin / admin)")
    try:
        app.run(host=host, port=port, threaded=True, use_reloader=False)
    finally:
        if engine:
            engine.stop()


if __name__ == "__main__":
    main()
