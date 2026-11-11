# PayLite

Dockerized three-tier digital wallet demo: React/Vite, FastAPI, and PostgreSQL.

## Run

```bash
docker compose up --build
```

Open http://localhost:5173. The API is at http://localhost:8000/docs.

Register a user with `POST /api/auth/register`, then log in. A seeded admin is available for the reversal demo: mobile `9999999999`, password `Admin123!`, PIN `1234`.

The backend uses database transactions, row locks, an append-only ledger, idempotency keys, daily transfer limits, PIN lockout, correlation IDs, and CSV statement export. PostgreSQL data persists in the `postgres_data` Docker volume.
