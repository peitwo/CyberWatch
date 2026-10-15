# CyberWatch V0.1

A beginner-friendly FastAPI security incident tracking API. Uses fictional incident data only.

## Requirements

Python 3.11+ (3.12 recommended), Git, VS Code / Cursor.

## Windows PowerShell quickstart

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Visit http://127.0.0.1:8000/docs and try POST /events with:

```json
{"title":"Repeated login failures","severity":"high","description":"Simulated lab event"}
```

Try GET /events, PATCH /events/{event_id}, DELETE /events/{event_id}.

## Tests

Open a second terminal:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Git

```powershell
git init
git add .
git commit -m "feat: bootstrap CyberWatch event API"
```

If git commit requests identity, set your `git config --global user.name` and `git config --global user.email` first.

## Architecture

- `app/main.py`: FastAPI routes and SQLModel models
- `tests/test_events.py`: CRUD / validation API tests
- `cyberwatch.db`: local SQLite database, generated automatically

## Important limitations

- Local learning prototype; **not safe for public deployment** yet.
- No login, roles, audit trail, production config or database migrations.
- SQLite `create_all()` cannot perform schema migration on existing tables.
- Next milestones: project layering, authentication, React, PostgreSQL, automated testing, Docker, deployment.

## Personal learning tasks

1. Add a `status` field with `open`, `investigating`, and `closed` choices.
2. Create a test for filtering events by status.
3. Explain request -> API -> validation -> database -> response in your own words.
4. For database schema changes, remove local demo DB (only if disposable) or use migrations later.
