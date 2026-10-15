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

## Database schema migrations (Alembic)

Schema changes are owned by Alembic — the app never alters the database itself.
Because the default database URL now points at `<project root>/cyberwatch.db`
(an absolute path, independent of the current working directory), the server no
longer creates the file for you: run the migration first.

```powershell
# 1) inspect the SQL that would run (offline, prints only, touches nothing)
.\.venv\Scripts\python.exe -m alembic upgrade head --sql

# 2) create / update the schema
.\.venv\Scripts\python.exe -m alembic upgrade head

# 3) start the server
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

If the database already has the `event` table but no `alembic_version` table
(a database created by the old `create_all()` code path), claim the baseline
revision once before upgrading:

```powershell
.\.venv\Scripts\python.exe -m alembic stamp 0001
.\.venv\Scripts\python.exe -m alembic upgrade head
```

Running `alembic` from a different directory is not supported: `alembic.ini`
lives next to the `migrations/` folder.

### Changing where the database lives

Set the environment variable `CYBERWATCH_DATABASE_URL` to override it
(tests and deployment use this; it takes priority over the default path):

```powershell
$env:CYBERWATCH_DATABASE_URL = "sqlite:///C:/temp/scratch.db"
```

Resolution priority, highest first: a `sqlalchemy.url` passed programmatically
(tests), then `CYBERWATCH_DATABASE_URL`, then `<project root>/cyberwatch.db`.
`app/config.py` is the single implementation used by both the app and Alembic,
so the app and the migration can never target two different files.

## Tests

Open a second terminal:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

`tests/conftest.py` redirects the default database into a system temp directory
before `app` is imported, so the test suite can never touch your real
`cyberwatch.db`. Migration tests use their own throwaway databases and assert
that those paths are inside the system temp directory.

## Git

```powershell
git init
git add .
git commit -m "feat: bootstrap CyberWatch event API"
```

If git commit requests identity, set your `git config --global user.name` and `git config --global user.email` first.

## Architecture

- `app/main.py`: FastAPI routes and SQLModel models
- `app/config.py`: single source of truth for the project path and the database URL
- `migrations/`: Alembic environment and version scripts (`0001` baseline, `0002` adds `event.status`)
- `tests/test_events.py`: CRUD / validation API tests
- `tests/test_status.py`, `tests/test_config.py`, `tests/test_migrations.py`: lifecycle status, database-URL resolution, and migration tests
- `cyberwatch.db`: local SQLite database, created by `alembic upgrade head`

## Important limitations

- Local learning prototype; **not safe for public deployment** yet.
- No login, roles or audit trail.
- Schema changes must go through Alembic; the app only performs a read-only
  schema check at startup and refuses to serve if a migration is missing.
- Next milestones: project layering, authentication, React, PostgreSQL, Docker, deployment.

## Personal learning tasks

1. Add a `status` field with `open`, `investigating`, and `closed` choices.
2. Create a test for filtering events by status.
3. Explain request -> API -> validation -> database -> response in your own words.
4. For database schema changes, remove local demo DB (only if disposable) or use migrations later.
