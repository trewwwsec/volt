import compileall
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "volt.py",
    "volt_version.py",
    "cli.py",
    "constants.py",
    "core.py",
    "models.py",
    "networking.py",
    "parsing.py",
    "reporting.py",
    "volt_models.py",
    "volt_reporting.py",
)
DIRECTORIES = ("sources", "tests", "scripts")


def main() -> int:
    missing = [name for name in FILES if not (ROOT / name).is_file()]
    missing += [name for name in DIRECTORIES if not (ROOT / name).is_dir()]
    if missing:
        print("Missing compile targets: " + ", ".join(missing))
        return 1
    results = [compileall.compile_file(ROOT / name, quiet=1) for name in FILES]
    results += [compileall.compile_dir(ROOT / name, quiet=1) for name in DIRECTORIES]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
