# Password Security Toolkit

A comprehensive password security toolkit built with Python and Flask. The toolkit provides a password strength analyzer, secure password generator, breach checker powered by the haveibeenpwned API, policy validator, and a web dashboard with visualizations.

## Features

- **Password strength analyzer**: Calculates entropy, detects weak patterns (repetitions, sequences, common passwords), and offers actionable suggestions.
- **Secure password generator**: Creates passwords using cryptographically secure randomness with customizable character sets and enforcement of category requirements.
- **Password breach checker**: Uses the haveibeenpwned k-anonymity API to determine if a password has appeared in known breaches while preserving privacy.
- **Policy validator**: Validates passwords against configurable organizational policies (length, character diversity, repetition, and sequence rules).
- **Flask web interface**: Single-page dashboard that ties everything together with charts illustrating strength metrics and tables summarizing policy compliance.

## Getting started

### Prerequisites

- Python 3.10+
- Optional: a virtual environment (recommended)

### Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

### Running the development server

```bash
flask --app run run --debug
```

The web interface will be available at <http://127.0.0.1:5000>. Use the analyzer section to evaluate existing passwords (or passphrases) and the generator to create new, policy-compliant secrets.

> **Note:** Network access is required for breach checks. If the haveibeenpwned API is unreachable, the toolkit will fall back gracefully and mark the password as not found.

## Command-line usage examples

The core functionality is exposed as importable modules under `password_toolkit/`. Example usage:

```python
from password_toolkit.analyzer import PasswordStrengthAnalyzer
from password_toolkit.generator import PasswordGenerator, GenerationOptions
from password_toolkit.breach_checker import BreachChecker
from password_toolkit.policy import Policy, PolicyValidator

analyzer = PasswordStrengthAnalyzer()
report = analyzer.analyze("CorrectHorseBatteryStaple!")
print(report.entropy, report.issues)

generator = PasswordGenerator(GenerationOptions(length=20, use_symbols=False))
print(generator.generate())

breach_result = BreachChecker().check_password("hunter2")
print(breach_result.found, breach_result.count)

policy = Policy(min_length=16, require_symbols=False)
validator = PolicyValidator(policy)
print(validator.is_valid("S3curePassphrase"))
```

## Security best practices

- Use long, unique passwords or passphrases for every account to contain potential breaches.
- Enable multi-factor authentication wherever possible.
- Store credentials in a reputable password manager instead of reusing or writing them down.
- Rotate passwords immediately if the breach checker indicates exposure.
- Avoid transmitting or storing plaintext passwords; prefer password hashes using strong algorithms such as Argon2id when integrating with authentication systems.

## Project structure

```
├── app/
│   ├── __init__.py        # Flask application factory
│   ├── routes.py          # HTTP routes and view logic
│   ├── static/
│   │   └── js/dashboard.js
│   └── templates/
│       ├── base.html
│       └── index.html
├── password_toolkit/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── breach_checker.py
│   ├── generator.py
│   └── policy.py
├── requirements.txt
└── run.py
```

## Testing ideas

- Add unit tests for entropy calculations, generator options, and policy validation to ensure regression coverage.
- Mock the haveibeenpwned API to test breach-check failure scenarios without performing live HTTP calls.

## License

This project is provided as-is for educational purposes. Evaluate and adapt it before using in production environments.
