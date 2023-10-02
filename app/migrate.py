from pymongo.mongo_client import MongoClient

uri = "mongodb+srv://root:password@db:27018/?retryWrites=true&w=majority"

# Create a new client and connect to the server
client = MongoClient(uri)

auth_db = client["archisoft"]["auth"]
permissions_db = client["archisoft"]["permissions"]
roles_db = client["archisoft"]["roles"]


auth_db.insert_many(
    [
        {
            "id": "1",
            "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
            "role": "admin",
            "user_id": "1",
        },
        {
            "id": "2",
            "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
            "role": "patient",
            "user_id": "2",
        },
    ]
)

permissions_db.insert_one(
    {
        "url": "/appointments",
        "admin": ["GET", "POST", "PUT", "DELETE"],
        "patient": ["GET"]
    }
)
