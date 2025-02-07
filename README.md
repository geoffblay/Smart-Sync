* start app: gunicorn app:app --bind 0.0.0.0:5001 --log-level debug
* start firestore emulator: firebase emulators:start --only firestore
* expose server: ngrok http 5001 --url https://organic-certain-joey.ngrok-free.app

* available at: localhost:5001
