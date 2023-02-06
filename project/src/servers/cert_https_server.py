from flask import Flask

app = Flask(__name__)
port = 5001


@app.route("/")
def hello():
    print("CERTIFICATE SERVER: Got a request")
    return "I'm using HTTPS!"


def launch_https_server(key_path, certificate_path):
    app.run(host="0.0.0.0",
            port=port,
            ssl_context=(certificate_path, key_path))


if __name__ == '__main__':
    pass