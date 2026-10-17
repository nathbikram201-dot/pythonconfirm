FLIENT-PAPA Render + Firebase setup

FILES: bot.py, requirements.txt, admin.html, render.yaml

RENDER BACKEND
1. Upload these files to a PRIVATE GitHub repository.
2. Create a Render Web Service from that repository.
   Build command: pip install -r requirements.txt
   Start command: gunicorn bot:app --bind 0.0.0.0:$PORT --workers 1 --threads 4
3. In Render Environment set ADMIN_KEY to a strong private key (do not use BIKRAM for production).
4. Firebase persistence: in Firebase Console enable Firestore Database, create a service-account key JSON, then put the entire JSON content in Render environment variable FIREBASE_SERVICE_ACCOUNT_JSON. Never upload this private key to GitHub.
5. Deploy. Copy the Render URL, e.g. https://your-service.onrender.com

ADMIN PANEL CAN BE HOSTED ANYWHERE
- Open admin.html locally or upload it to any static website hosting.
- In the Backend URL box, paste your Render URL and press Save backend URL.
- Login with the ADMIN_KEY configured on Render. The browser calls the Render API; it does not connect directly to Firestore.
- If the admin panel is hosted on a different domain, the backend allows cross-origin API calls. Keep the admin key private and use HTTPS.

TOKEN FLOW
- Generate a token with validity in minutes; the returned URL is https://your-service.onrender.com/access/TOKEN.
- The endpoint checks token expiry/revocation server-side before returning the configuration JSON.
- The configuration JSON must be delivered to the VPN client, so it cannot be guaranteed secret from someone who can use that client and URL.

LOCAL TEST
  pip install -r requirements.txt
  ADMIN_KEY=BIKRAM python bot.py
  open http://127.0.0.1:8080/admin.html
If FIREBASE_SERVICE_ACCOUNT_JSON is absent, SQLite is used only for local testing. Render's ephemeral disk can reset it; configure Firebase for persistent token records.

IMPORTANT FIREBASE NOTE
The Firebase Web SDK config (apiKey/authDomain/projectId/etc.) is for browser-side Firebase SDKs and is not sufficient for secure server-side Firestore access. This backend uses Firebase Admin SDK with FIREBASE_SERVICE_ACCOUNT_JSON stored only in Render Environment. Do not put service-account credentials in admin.html.
