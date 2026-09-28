"""Small, intentionally vulnerable project for a local demo."""

import subprocess


def display_name(name: str) -> str:
    return f"Hello, {name}!"


def list_user_files(name: str) -> str:
    result = subprocess.run(
        f"ls /home/{name}", shell=True, capture_output=True, text=True
    )
    return result.stdout


def find_user(cursor, name: str):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")


def load_settings(data: str):
    import yaml

    return yaml.load(data, Loader=yaml.Loader)
