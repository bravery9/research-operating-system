from fastapi import FastAPI
import requests

app = FastAPI()


@app.post("/upload")
def upload(url: str) -> dict[str, bool]:
    with open("/tmp/upload.txt", "w") as handle:
        handle.write(url)
    requests.get(url)
    return {"ok": True}
