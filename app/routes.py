"""Flask routes for password security toolkit."""
from __future__ import annotations

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from password_toolkit.analyzer import PasswordStrengthAnalyzer
from password_toolkit.breach_checker import BreachChecker
from password_toolkit.generator import GenerationOptions, PasswordGenerator
from password_toolkit.policy import PolicyValidator

bp = Blueprint("password_toolkit", __name__)

analyzer = PasswordStrengthAnalyzer()
breach_checker = BreachChecker()
policy_validator = PolicyValidator()

default_generation_options = GenerationOptions()

def _parse_bool(value: str | None) -> bool:
    return value is not None and value.lower() in {"on", "true", "1"}


def _parse_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


@bp.route("/", methods=["GET", "POST"])
def index():
    password = ""
    report = None
    breach_result = None
    policy_checks = None
    generated_password = request.args.get("generated")
    error_message = request.args.get("error")

    if request.method == "POST":
        password = request.form.get("password", "")
        report = analyzer.analyze(password)
        breach_result = breach_checker.check_password(password)
        policy_checks = policy_validator.validate(password)

    return render_template(
        "index.html",
        password=password,
        report=report,
        breach_result=breach_result,
        policy_checks=policy_checks,
        generation_options=default_generation_options,
        generated_password=generated_password,
        error_message=error_message,
    )


@bp.route("/generate", methods=["POST"])
def generate_password():
    length = _parse_int(request.form.get("length"), default_generation_options.length)
    options = GenerationOptions(
        length=length,
        use_lowercase=_parse_bool(request.form.get("use_lowercase")),
        use_uppercase=_parse_bool(request.form.get("use_uppercase")),
        use_digits=_parse_bool(request.form.get("use_digits")),
        use_symbols=_parse_bool(request.form.get("use_symbols")),
        require_each_category=_parse_bool(request.form.get("require_each_category")),
    )

    generator = PasswordGenerator(options)
    try:
        password = generator.generate()
        if request.form.get("format") == "json":
            return jsonify({"password": password})
        return redirect(url_for("password_toolkit.index", generated=password))
    except ValueError as exc:
        if request.form.get("format") == "json":
            return jsonify({"error": str(exc)}), 400
        return redirect(url_for("password_toolkit.index", error=str(exc)))


@bp.route("/policy", methods=["GET"])
def policy_requirements():
    return jsonify(policy_validator.policy.__dict__)
