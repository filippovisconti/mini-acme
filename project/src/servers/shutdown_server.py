import os, signal, requests
from flask import Flask, request

app = Flask(__name__)
port = 5003


@app.route('/shutdown', methods=['GET'])
def stopServer():
    print("Bye bye")
    os.kill(os.getpid(), signal.SIGTERM)  # Management server
    return "Server on port 5003 is shutting everything down."


def launch_shutdown_server() -> None:
    print("START https")
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)


if __name__ == '__main__':
    print("START https")
    app.run(host="0.0.0.0", port=port)