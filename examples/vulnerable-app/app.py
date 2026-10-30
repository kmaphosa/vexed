"""Tiny config-upload service used as a VEXed demo target. Intentionally vulnerable."""
import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)

PAGE = "<h1>Hello {{ name }}</h1><p>Plugins: {{ plugins|length }}</p>"


@app.route("/config", methods=["POST"])
def upload_config():
    # Attacker-controlled YAML parsed with FullLoader
    cfg = yaml.load(request.data, Loader=yaml.FullLoader)
    return {"keys": list(cfg)}


@app.route("/hello/<name>")
def hello(name):
    return render_template_string(PAGE, name=name, plugins=[])


@app.route("/status")
def status():
    r = requests.get("https://status.example.com/api", timeout=5)
    return {"upstream": r.status_code}


if __name__ == "__main__":
    app.run()
