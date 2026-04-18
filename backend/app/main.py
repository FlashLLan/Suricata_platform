from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import auth, projects, simulation, pcap

# Create all tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Suricata Learning Platform API",
    description="Backend for the Suricata visual simulation and learning platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(simulation.router)
app.include_router(pcap.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
