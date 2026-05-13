from flask import Flask, render_template

app = Flask(__name__)


@app.route("/preview")
def preview() -> str:
    return render_template("preview.html")
