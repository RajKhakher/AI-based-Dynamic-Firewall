"""
server.py - the Flask dashboard and its JSON API.

The dashboard is how you watch and control the firewall in a browser. It talks
to the running engine directly (same process), so everything is live.

Security basics that the old version was missing:
  * login required for every page and API call
  * passwords stored hashed, not in plain text (see auth.py)
  * a random secret key each run, so sessions can't be forged across restarts
  * a CSRF token required on every state-changing (POST) request, so another
    website can't trick your browser into changing firewall rules
  * the server binds to 127.0.0.1 by default (local only)

If the engine is None (dashboard started with --web-only) the live controls are
disabled and you just get the stored history.
"""

from __future__ import annotations

import functools
import os
import secrets

from flask import (Flask, jsonify, redirect, render_template, request,
                   session, url_for)

from fwcore import config
from fwcore.storage import Storage
from . import auth


def create_app(engine=None) -> Flask:
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)          # new key each run
    app.config["engine"] = engine
    # A storage handle for read-only history (works even without the engine).
    app.config["storage"] = engine.storage if engine else Storage()

    auth.ensure_default_admin()

    # -- helpers ------------------------------------------------------------
    def login_required(view):
        @functools.wraps(view)
        def wrapped(*a, **kw):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "auth required"}), 401
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapped

    def csrf_ok() -> bool:
        token = session.get("csrf")
        sent = request.headers.get("X-CSRF-Token")
        if not sent:
            if request.is_json:
                sent = (request.json or {}).get("csrf")
            else:
                sent = request.form.get("csrf")
        return bool(token) and secrets.compare_digest(str(token), str(sent or ""))

    def require_engine():
        eng = app.config["engine"]
        if eng is None:
            return None, (jsonify({"error": "engine not running (dashboard is view-only)"}), 503)
        return eng, None

    # -- auth routes --------------------------------------------------------
    @app.route("/", methods=["GET", "POST"])
    def login():
        if session.get("user"):
            return redirect(url_for("dashboard"))
        error = None
        if request.method == "POST":
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if auth.validate(u, p):
                session["user"] = u
                session["csrf"] = secrets.token_hex(16)
                return redirect(url_for("dashboard"))
            error = "Invalid username or password."
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            user=session["user"],
            csrf=session["csrf"],
            must_change=auth.is_default_password(session["user"]),
            has_engine=app.config["engine"] is not None,
        )

    @app.route("/api/change-password", methods=["POST"])
    @login_required
    def change_password():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        new = (request.json or {}).get("password", "")
        if len(new) < 6:
            return jsonify({"error": "password must be at least 6 characters"}), 400
        auth.set_password(session["user"], new)
        return jsonify({"ok": True})

    # -- read API -----------------------------------------------------------
    @app.route("/api/status")
    @login_required
    def api_status():
        eng = app.config["engine"]
        if eng is None:
            return jsonify({"engine": False, "mode": "offline"})
        s = eng.status()
        s["engine"] = True
        return jsonify(s)

    @app.route("/api/events")
    @login_required
    def api_events():
        limit = min(int(request.args.get("limit", 100)), 500)
        return jsonify(app.config["storage"].recent_events(limit))

    @app.route("/api/alerts")
    @login_required
    def api_alerts():
        limit = min(int(request.args.get("limit", 100)), 500)
        return jsonify(app.config["storage"].recent_alerts(limit))

    @app.route("/api/blocks")
    @login_required
    def api_blocks():
        eng = app.config["engine"]
        active = eng.blocklist.active() if eng else []
        return jsonify({"active": active,
                        "history": app.config["storage"].recent_blocks(50)})

    @app.route("/api/rules")
    @login_required
    def api_rules():
        eng = app.config["engine"]
        if eng is None:
            from fwcore.rules import RuleSet
            return jsonify(RuleSet().load().all())
        return jsonify(eng.rules.all())

    # -- write API (all require CSRF + engine) -----------------------------
    @app.route("/api/mode", methods=["POST"])
    @login_required
    def api_mode():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        mode = (request.json or {}).get("mode")
        if mode not in ("monitor", "enforce"):
            return jsonify({"error": "mode must be monitor or enforce"}), 400
        eng.set_mode(mode)
        return jsonify({"ok": True, "mode": mode})

    @app.route("/api/block", methods=["POST"])
    @login_required
    def api_block():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        data = request.json or {}
        ip = data.get("ip", "").strip()
        seconds = int(data.get("seconds", 0) or 0)
        if not ip:
            return jsonify({"error": "ip required"}), 400
        ok = eng.blocklist.block(ip, seconds, reason="manual (dashboard)", source="manual")
        if not ok:
            return jsonify({"error": "could not block (safelisted or already blocked)"}), 400
        return jsonify({"ok": True})

    @app.route("/api/unblock", methods=["POST"])
    @login_required
    def api_unblock():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        ip = (request.json or {}).get("ip", "").strip()
        eng.blocklist.unblock(ip)
        return jsonify({"ok": True})

    @app.route("/api/rules", methods=["POST"])
    @login_required
    def api_rules_add():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        try:
            rule = eng.rules.add(request.json or {})
            return jsonify({"ok": True, "rule": rule.to_dict()})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
    @login_required
    def api_rules_delete(rule_id):
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        ok = eng.rules.delete(rule_id)
        return jsonify({"ok": ok})

    @app.route("/api/rules/<int:rule_id>", methods=["PUT"])
    @login_required
    def api_rules_update(rule_id):
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        rule = eng.rules.update(rule_id, request.json or {})
        return jsonify({"ok": bool(rule), "rule": rule.to_dict() if rule else None})

    # -- AI controls --------------------------------------------------------
    @app.route("/api/ai/learn", methods=["POST"])
    @login_required
    def api_ai_learn():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        action = (request.json or {}).get("action")
        if action == "start":
            eng.ai.start_learning()
        elif action == "stop":
            eng.ai.stop_learning()
        return jsonify({"ok": True, "ai": eng.ai.status()})

    @app.route("/api/ai/train", methods=["POST"])
    @login_required
    def api_ai_train():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        result = eng.ai.train()
        return jsonify(result)

    @app.route("/api/ai/autoblock", methods=["POST"])
    @login_required
    def api_ai_autoblock():
        if not csrf_ok():
            return jsonify({"error": "bad csrf"}), 403
        eng, err = require_engine()
        if err:
            return err
        on = bool((request.json or {}).get("enabled"))
        eng.cfg = config.update(["ai", "auto_block"], on)
        return jsonify({"ok": True, "auto_block": on})

    return app
