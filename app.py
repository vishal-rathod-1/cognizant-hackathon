import os, base64
from datetime import timedelta
from flask import Flask, render_template, request, redirect, session, url_for, flash
from sqlalchemy import create_engine, select, delete
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base, User, PIIRecord
from crypto_utils import (
    new_salt_b64, sha256_auth_hash, derive_key, aesgcm_encrypt,validate_password, aesgcm_decrypt, PBKDF2_ITERS, b64e
)
import re
from flask import flash, redirect, render_template, request, session, url_for
from sqlalchemy import select


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///cipherkeep_ui.db")
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32))

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, PERMANENT_SESSION_LIFETIME=timedelta(hours=1))

engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))

def db_sess():
    return SessionLocal()

@app.context_processor
def inject_globals():
    return dict(app_name="CipherKeep UI", username=session.get("username"))

@app.get("/")
def index():
    db = db_sess()
    try:
        user_count = db.query(User).count()
    finally:
        db.close()
    return render_template("index.html", title="Home", user_count=user_count)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", title="Register")

    username = request.form.get("username","").strip()
    password = request.form.get("password","")

    if not username or not password:
        flash("Please provide username and password.", "danger")
        return redirect(url_for("register"))

    # ✅ Password policy check here
    valid, msg = validate_password(password)
    if not valid:
        flash(msg, "danger")
        return redirect(url_for("register"))

    db = db_sess()
    try:
        exists = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if exists:
            flash("Username already exists.", "warning")
            return redirect(url_for("register"))

        auth_salt_b64 = new_salt_b64()
        kdf_salt_b64  = new_salt_b64()
        auth_hash_b64 = b64e(sha256_auth_hash(password, auth_salt_b64))

        user = User(username=username, auth_salt_b64=auth_salt_b64,
                    auth_hash_b64=auth_hash_b64, kdf_salt_b64=kdf_salt_b64,
                    kdf_iters=PBKDF2_ITERS)
        db.add(user); db.commit()

        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    finally:
        db.close()


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", title="Login")
    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    db = db_sess()
    try:
        user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if not user:
            flash("Invalid credentials.", "danger"); return redirect(url_for("login"))
        calc = b64e(sha256_auth_hash(password, user.auth_salt_b64))
        if calc != user.auth_hash_b64:
            flash("Invalid credentials.", "danger"); return redirect(url_for("login"))
        # derive AES key for session
        key = derive_key(password, user.kdf_salt_b64, user.kdf_iters)
        session.clear()
        session["uid"] = user.id
        session["username"] = user.username
        session["key_b64"] = base64.b64encode(key).decode()
        session.permanent = True
        flash("Welcome back!", "success")
        return redirect(url_for("pii"))
    finally:
        db.close()

@app.get("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


@app.route("/pii", methods=["GET", "POST"])
def pii():
    if "uid" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    db = db_sess()
    try:
        user = db.get(User, session["uid"])
        
        if request.method == "POST":
            incoming = {
                "name": request.form.get("name", "").strip(),
                "email": request.form.get("email", "").strip(),
                "phone": request.form.get("phone", "").strip(),
                "address": request.form.get("address", "").strip(),
            }

            # ---------------------------
            # VALIDATION
            # ---------------------------
            errors = []

            # Validate email format
            if incoming["email"]:
                email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
                if not re.match(email_regex, incoming["email"]):
                    errors.append("Invalid email format.")

            # Validate phone number (10 digits only)
            if incoming["phone"]:
                phone_regex = r'^\d{10}$'
                if not re.match(phone_regex, incoming["phone"]):
                    errors.append("Phone number must be exactly 10 digits.")

            # If there are validation errors, stop and return
            if errors:
                for err in errors:
                    flash(err, "danger")
                return redirect(url_for("pii"))

            # ---------------------------
            # ENCRYPT & SAVE
            # ---------------------------
            key = base64.b64decode(session["key_b64"])
            saved = 0

            for field, value in incoming.items():
                if not value:
                    continue

                aad = f"{user.username}|{field}".encode()
                nonce_b64, ct_b64 = aesgcm_encrypt(key, value.encode(), aad)

                # Upsert: delete existing field, then add new
                exist = db.execute(
                    select(PIIRecord).where(
                        PIIRecord.owner_id == user.id,
                        PIIRecord.field_name == field
                    )
                ).scalar_one_or_none()

                if exist:
                    db.delete(exist)

                rec = PIIRecord(
                    owner_id=user.id,
                    field_name=field,
                    nonce_b64=nonce_b64,
                    ciphertext_b64=ct_b64
                )
                db.add(rec)
                saved += 1

            if saved:
                db.commit()
                flash("Saved & encrypted your fields.", "success")
            else:
                flash("Nothing to save.", "warning")

            return redirect(url_for("pii"))

        # ---------------------------
        # GET: FETCH & DECRYPT
        # ---------------------------
        key = base64.b64decode(session["key_b64"])
        records = db.execute(
            select(PIIRecord).where(PIIRecord.owner_id == user.id)
        ).scalars().all()

        decrypted = {}
        for r in records:
            try:
                aad = f"{user.username}|{r.field_name}".encode()
                pt = aesgcm_decrypt(key, r.nonce_b64, r.ciphertext_b64, aad).decode()
                decrypted[r.field_name] = pt
            except Exception:
                decrypted[r.field_name] = "***DECRYPTION_ERROR***"

        return render_template("pii.html", title="My PII", decrypted=decrypted, records=records)

    finally:
        db.close()


@app.route("/change-password", methods=["GET","POST"])
def change_password():
    if "uid" not in session: 
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    db = db_sess()
    try:
        user = db.get(User, session["uid"])

        if request.method == "GET":
            return render_template("change_password.html", title="Change Password")

        old_pw = request.form.get("old_password","")
        new_pw = request.form.get("new_password","")

        if not old_pw or not new_pw:
            flash("Both old and new passwords are required.", "danger")
            return redirect(url_for("change_password"))

        # ✅ verify old password
        calc = b64e(sha256_auth_hash(old_pw, user.auth_salt_b64))
        if calc != user.auth_hash_b64:
            flash("Old password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        # ✅ enforce password policy on new password
        valid, msg = validate_password(new_pw)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("change_password"))

        # derive keys
        old_key = derive_key(old_pw, user.kdf_salt_b64, user.kdf_iters)
        new_key = derive_key(new_pw, user.kdf_salt_b64, user.kdf_iters)

        # re-encrypt all user PII rows
        rows = db.execute(select(PIIRecord).where(PIIRecord.owner_id==user.id)).scalars().all()
        reenc = 0
        for r in rows:
            try:
                aad = f"{user.username}|{r.field_name}".encode()
                pt = aesgcm_decrypt(old_key, r.nonce_b64, r.ciphertext_b64, aad)
                nonce_b64, ct_b64 = aesgcm_encrypt(new_key, pt, aad)
                r.nonce_b64 = nonce_b64
                r.ciphertext_b64 = ct_b64
                reenc += 1
            except Exception:
                pass

        # update auth hash to new password (keeping same auth_salt for simplicity)
        user.auth_hash_b64 = b64e(sha256_auth_hash(new_pw, user.auth_salt_b64))
        db.commit()

        # update session key
        session["key_b64"] = base64.b64encode(new_key).decode()
        flash(f"Password changed. Re-encrypted {reenc} record(s).", "success")
        return redirect(url_for("pii"))

    finally:
        db.close()

if __name__ == "__main__":
    app.run(debug=True)
