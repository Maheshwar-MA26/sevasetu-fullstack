# SEVASETU — Full-Stack Hackathon MVP v6

## What's improved in v6
- Portal-wide language switching across login, dashboard, services, schemes, documents, applications, notifications, profile, settings and SEVA AI UI.
- Supported portal languages: English, Hindi, Marathi, Bengali, Gujarati, Tamil and Telugu.
- Language choice is persisted in the browser and also updates speech recognition/text-to-speech language.
- Logged-in citizen name is taken from the actual authenticated account returned by the backend.
- Registration and OTP verification now save the authenticated user into the frontend session.
- On page refresh, the frontend calls `/api/me` and restores the real account name.
- Sidebar/header avatar uses the logged-in citizen's first initial instead of a fixed person.
- Guest mode is explicitly labelled `Guest Citizen` instead of showing a fake citizen name.
- When MongoDB is unavailable, the backend uses a local `fallback-db.json` so registered demo accounts persist across server restarts.

## Run
```bash
npm run install:all
npm run dev
```
Open `http://localhost:5173`.

Backend: `http://localhost:5000/api/health`

## Demo OTP
In development, OTP is printed in the server terminal. A real SMS provider is not connected in this hackathon MVP.

## MongoDB
If `MONGODB_URI` is configured and reachable, MongoDB is used. Otherwise the local fallback database is used.
