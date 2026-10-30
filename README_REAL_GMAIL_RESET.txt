PROEXAM — UPDATED LOGIN, REGISTRATION OTP & PASSWORD RESET OTP

SETUP (Windows)
1. Extract this ZIP to a normal folder.
2. Open that folder and confirm package.json is beside server.js.
3. Copy .env.example and name the copy .env.
4. In .env, enter your Gmail address in SMTP_USER and SMTP_FROM, and a Google App Password in SMTP_PASS. Remove spaces from the App Password. Never use your normal Gmail password.
5. Open CMD in this project folder (File Explorer address bar -> type cmd -> Enter).
6. Run: npm.cmd install
7. Run: npm.cmd start
8. Open: http://localhost:3000

EMAIL OTP FEATURES
- New student registration sends a 6-digit email OTP before creating the account.
- Forgot Password sends a 6-digit OTP to the registered email.
- OTPs expire after 10 minutes, are hashed in storage, and are limited to five verification attempts.
- Resend is rate-limited to once per 60 seconds per email and purpose.
- Student IDs are generated from college prefix + roll number (example GPV34).
- Login pages have Show/Hide Password controls.

GMAIL SETUP
- Enable 2-Step Verification on the Gmail account.
- Create a Google App Password and place it in SMTP_PASS.
- Make sure this computer has internet access while sending OTP emails.
- If email fails, check the CMD error and verify SMTP_USER/SMTP_PASS. This package intentionally does not include your private .env file.

IMPORTANT
- Do not share .env or upload it to a public repository.
- localhost links work only on the computer running the server.
- For public deployment, use HTTPS, server-side sessions/cookies, stronger rate limiting, and review all authorization checks before production use.
- Do not delete server-data/students.json or server-data/admins.json if you want to preserve existing accounts.
