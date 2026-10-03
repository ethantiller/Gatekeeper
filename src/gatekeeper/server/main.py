"""Server startup and route mounting."""
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

def run():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8787)
