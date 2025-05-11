# Password Manager with High-Grade Security

A secure web-based password manager built with Flask, SQLAlchemy, and strong encryption. Supports deployment on Render with PostgreSQL.

## Features
- User registration and login with strong password policy
- Passwords are encrypted using Fernet symmetric encryption
- User passwords are hashed with PBKDF2 (480,000 iterations)
- Secure session management
- Responsive web UI (Tailwind CSS)
- Ready for cloud deployment (Render)

## Requirements
- Python 3.7+
- PostgreSQL database (for production)

## Setup (Local)
1. **Clone the repository and navigate to the project folder.**
2. **Create a virtual environment (optional but recommended):**
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
4. **Create a `.env` file (optional for local secrets):**
   ```env
   SECRET_KEY=your_secret_key_here
   DATABASE_URL=sqlite:///passwords.db
   ```
5. **Create a `templates` folder and add the HTML files:**
   - `base.html`, `login.html`, `register.html`, `dashboard.html`, `add_password.html`

6. **Run the app:**
   ```sh
   python "Password manager.py"
   ```
   The app will be available at [http://localhost:10000](http://localhost:10000)

## Deployment on Render
1. **Provision a PostgreSQL database on Render.**
2. **Set the `DATABASE_URL` and `SECRET_KEY` environment variables in your Render web service.**
3. **Ensure your `requirements.txt` includes `psycopg2-binary`.**
4. **Push your code to GitHub.**
5. **Add a `render.yaml` file (already included):**
   ```yaml
   services:
     - type: web
       name: password-manager
       env: python
       buildCommand: pip install -r requirements.txt
       startCommand: python "Password Manager with Military-Grade S.py"
   ```
6. **Deploy the web service on Render.**

## Security Notes
- All passwords are encrypted before storage.
- User passwords are never stored in plaintext.
- Use strong, unique `SECRET_KEY` and database credentials in production.

## License
MIT 
