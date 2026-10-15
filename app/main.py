"""CyberWatch V0.1: a learning-oriented security event API."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ConfigDict
from sqlmodel import Field, Session, SQLModel, create_engine, select

# app/main.py -> app/ -> cyberwatch-starter/
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = "sqlite:///./cyberwatch.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class EventBase(SQLModel):
    title: str = Field(min_length=3, max_length=100)
    severity: Severity = Severity.low
    description: str = Field(default="", max_length=1000)


class Event(EventBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EventCreate(EventBase):
    pass


class EventUpdate(SQLModel):
    title: str | None = Field(default=None, min_length=3, max_length=100)
    severity: Severity | None = None
    description: str | None = Field(default=None, max_length=1000)


class EventRead(EventBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    SQLModel.metadata.create_all(engine)
    yield


app = FastAPI(title="CyberWatch", version="0.1.0", lifespan=lifespan)


@app.get("/")
def home():
    return {"app": "CyberWatch", "version": "0.1.0", "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard")
def dashboard():
    return FileResponse(BASE_DIR / "templates" / "dashboard.html")


@app.post("/events", response_model=EventRead, status_code=201)
def create_event(payload: EventCreate, session: SessionDep):
    event = Event.model_validate(payload)
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


@app.get("/events", response_model=list[EventRead])
def list_events(session: SessionDep, severity: Severity | None = None,
                offset: int = Query(default=0, ge=0), limit: int = Query(default=20, ge=1, le=100)):
    statement = select(Event).order_by(Event.id.desc()).offset(offset).limit(limit)
    if severity:
        statement = select(Event).where(Event.severity == severity).order_by(Event.id.desc()).offset(offset).limit(limit)
    return session.exec(statement).all()


@app.get("/events/{event_id}", response_model=EventRead)
def get_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    return event


@app.patch("/events/{event_id}", response_model=EventRead)
def update_event(event_id: int, payload: EventUpdate, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    event.sqlmodel_update(payload.model_dump(exclude_unset=True))
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


@app.delete("/events/{event_id}", status_code=204)
def delete_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    session.delete(event)
    session.commit()


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
