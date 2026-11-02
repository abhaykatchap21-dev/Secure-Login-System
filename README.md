Secure Login System

A secure user authentication web application developed using Python Flask and SQLite as part of my Cybersecurity Internship at Thiranex.

Features

- User registration and login
- Password hashing using Bcrypt
- CSRF protection using Flask-WTF
- Login rate limiting to prevent brute-force attacks
- SQL injection protection using parameterized queries
- Protected dashboard
- Secure session handling
- Input validation

Technologies Used

- Python
- Flask
- SQLite
- Flask-Bcrypt
- Flask-WTF
- Flask-Limiter
- HTML and CSS

How to Run Locally

1. Clone this repository.
2. Create a virtual environment:
   "python -m venv .venv"
3. Activate it on Windows:
   ".venv\Scripts\activate"
4. Install dependencies:
   "pip install -r requirements.txt"
5. Set a SECRET_KEY environment variable in PowerShell.
6. Run:
   "python app.py"
7. Open "http://127.0.0.1:5000" in your browser.

Security Note

The SQLite database and secret key are not included in this repository. Use a strong secret key stored in an environment variable.

Internship Project

Developed as part of the Thiranex Cybersecurity Internship.