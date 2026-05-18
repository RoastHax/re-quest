from re_quest import Session

with Session(profile="android148") as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()
    print(data["http_version"])
    print(data["tls"]["ja3"])
