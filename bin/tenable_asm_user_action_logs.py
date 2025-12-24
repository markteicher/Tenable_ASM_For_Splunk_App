ASM_ENDPOINT = "https://asm.cloud.tenable.com/api/1.0/user-action-logs"

offset = 0
limit = 100

while True:
    params = {
        "offset": offset,
        "limit": limit
    }

    resp = session.get(ASM_ENDPOINT, headers=headers, params=params)
    resp.raise_for_status()

    payload = resp.json()
    records = payload.get("list", [])

    if not records:
        break

    for rec in records:
        print(json.dumps(rec, ensure_ascii=False))

    if len(records) < limit:
        break

    offset += limit
