import sqlite3
from pathlib import Path

# Build absolute path to DATA folder from the project root
ROOT_DIR = Path(__file__).resolve().parents[2]   # goes up to CW2_M0123456_CST1510
DATA_DIR = ROOT_DIR / "DATA"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "intelligence_platform.db"

conn = sqlite3.connect(DB_PATH)
dbObject = conn.cursor()

createScript = """ Create table if not exists users (
            Id integer primary key autoincrement , 
            Username text not null unique,
            password_hash text not null,
            Role text default ‘user’                      )"""
dbObject.execute(createScript)
conn.commit()