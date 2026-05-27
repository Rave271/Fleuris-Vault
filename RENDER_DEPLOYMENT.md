# Render Deployment Guide

This folder is ready to deploy as a Flask web service on Render.

## Render Settings

Use these settings when creating the Render service:

| Setting | Value |
| --- | --- |
| Root Directory | `student_folder/grp8/src` |
| Runtime | Python |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn 'app:create_app()' --workers 1 --bind 0.0.0.0:$PORT` |

The `Procfile` already contains the same start command, so Render can also detect it automatically when the root directory is set correctly.

## Environment Variables

Set these in Render:

```text
AEGIS_SECRET_KEY=<a long random secret value>
DATABASE_URL=<your postgres connection string>
```

Optional:

```text
FLASK_DEBUG=0
```

Do not commit a real secret key to GitHub.

## Why These Files Exist

`requirements.txt` includes Flask and Gunicorn. Gunicorn is the production WSGI server Render uses to run the app.

`Procfile` tells Render how to start the web process.

`runtime.txt` pins the Python version.

`.env.example` shows which environment variables are needed without exposing real secrets.

## Important Notes

- The app initializes PostgreSQL tables on startup via SQLAlchemy `create_all()`.
- The app uses one Gunicorn worker so the session secret stays simple for evaluation.
- Admins can view structured JSON logs at `/security-log`.

