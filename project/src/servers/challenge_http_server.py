import os, signal, requests
import threading
from flask import Flask, abort
from flask.wrappers import Response
import logging
import flask.cli

flask.cli.show_server_banner = lambda *args: None
port = 5002
tokens: dict[str, str] = {}  # dictionary of (token, token.thumbprint)

app = Flask(__name__)
app.logger.disabled = True
log = logging.getLogger('werkzeug')
log.disabled = True


@app.route("/.well-known/acme-challenge/<string:acme_token>", methods=["GET"])
def response_to_challenge(acme_token: str):
    if acme_token not in tokens.keys():
        abort(404, "Unknown token")
    else:
        print("CHALLENGE SERVER: Got a request")
        response = Response(tokens[acme_token])
        response.headers["Content-Type"] = "application/octet-stream"
        return response


def launch_challenge_server(new_tokens: dict[str, str]):
    if new_tokens != {}:
        tokens.update(new_tokens)
        app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
    else:
        raise SystemError("You need to provide tokens.")
