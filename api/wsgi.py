"""WSGI entrypoint; requires the environment variables from README."""
from .server import create_app

app = create_app()
