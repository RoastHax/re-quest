from re_quest import Session

with Session(profile="chrome") as session:
    response = session.get("https://example.com/")
    print(response.status_code)
    print(response.text[:200])
