from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Backend is running"}

@app.get("/api/actions")
def list_actions():
    # This will eventually load from the schemas
    return {"actions": []}
