#!/usr/bin/env python3
from database import init_database, DB_PATH

print("🚀 Initialisation de la base de données...")
init_database()
print(f"✅ Base créée: {DB_PATH}")
