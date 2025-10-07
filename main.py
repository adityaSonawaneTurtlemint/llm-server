from fastapi import FastAPI
from pydantic import BaseModel
from typing import List


app = FastAPI()

class Item(BaseModel):
    name: str
    description: str = None
    price: float
    tax: float = None


iteams = []

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/items/", response_model=Item)
def create_item(item: Item):
    iteams.append(item)
    return item