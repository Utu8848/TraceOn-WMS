from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify
from flask_cors import CORS
from flask import session
from flask import jsonify, request
from drive_utils import get_folder_id, share_folder, create_overseer_folder, list_screenshots, download_file_bytes
import re
import io
from drive_utils import drive_service
import base64
from flask import send_file
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
import textwrap
import requests

app = Flask(__name__)
app.secret_key = 'my_super_secure_traceon_key_123!'
CORS(app)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    overseer_code TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)''')
    conn.commit()
    conn.close()

@app.route('/api/check_overseer', methods=['POST'])
def check_overseer():
    data = request.get_json()
    ocode = data.get('overseer_code')

    if not ocode:
        return jsonify({"exists": False, "error": "Missing overseer_code"}), 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE overseer_code = ?", (ocode,))
    exists = cursor.fetchone() is not None
    conn.close()

    return jsonify({"exists": exists})

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        code = request.form['code']
        password = request.form['password']

        # Required fields validation
        if not all([username, email, code, password]):
            message = 'All fields are required.'
            return render_template('login.html', login_message=message)

        # Overseer code format check
        if not re.fullmatch(r'\d{4}', code):
            message = 'Overseer code must be a 4-digit number.'
            return render_template('login.html', login_message=message)


        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=? AND email=? AND overseer_code=?', (username, email, code))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[4], password):
            session['overseer_code'] = code
            session['email'] = email
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            message = 'Invalid credentials.'

    return render_template('login.html', login_message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        code = request.form['code']
        password_input = request.form['password']

        # Required fields validation
        if not all([username, email, code, password_input]):
            message = 'All fields are required.'
            return render_template('register.html', register_message=message)

        # Overseer code format check
        if not re.fullmatch(r'\d{4}', code):
            message = 'Overseer code must be a 4-digit number.'
            return render_template('register.html', register_message=message)

        # Email format check
        if '@' not in email or '.' not in email:
            message = 'Invalid email format.'
            return render_template('register.html', register_message=message)

        # Password strength validation
        if len(password_input) < 6:
            message = 'Password must be at least 6 characters long.'
            return render_template('register.html', register_message=message)
        elif not re.search(r'[A-Z]', password_input):
            message = 'Password must include at least one uppercase letter.'
            return render_template('register.html', register_message=message)
        elif not re.search(r'\d', password_input):
            message = 'Password must include at least one number.'
            return render_template('register.html', register_message=message)
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password_input):
            message = 'Password must include at least one special character.'
            return render_template('register.html', register_message=message)

        # Hash the password if valid
        password = generate_password_hash(password_input)

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, overseer_code, password) VALUES (?, ?, ?, ?)',
                           (username, email, code, password))
            conn.commit()
            conn.close()

            folder_id = create_overseer_folder(code)
            share_folder(folder_id, email)

            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            message = 'User with the same email or overseer code already exists.'

    return render_template('register.html', register_message=message)

@app.route('/dashboard')
def dashboard():
    if 'overseer_code' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html')

@app.route('/about')
def about():
    if 'overseer_code' not in session:
        return redirect(url_for('login'))
    return render_template("about.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/workers')
def show_workers():
    if 'overseer_code' not in session:
        return redirect(url_for('login'))

    try:
        ocode = session['overseer_code']
        conn = sqlite3.connect('manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, worker_code FROM workers WHERE overseer_code=?", (ocode,))
        raw_workers = cursor.fetchall()
        conn.close()

        return render_template('workers.html', workers=raw_workers)
    
    except sqlite3.OperationalError as e:
        if "no such table: workers" in str(e):
            return render_template('workers.html', workers=[])

@app.route('/worker/<worker_code>')
def list_worker_dates(worker_code):
    if 'overseer_code' not in session:
        return redirect(url_for('login'))

    ocode = session['overseer_code']
    conn = sqlite3.connect('manager.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM workers WHERE overseer_code=? AND worker_code=?", (ocode, worker_code))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return "Worker not found", 404

    username = result[0]
    worker_folder_name = f"{username}-{worker_code}"

    root_id = get_folder_id("TraceOnScreenshots")
    overseer_id = get_folder_id(ocode, parent_id=root_id)
    worker_id = get_folder_id(worker_folder_name, parent_id=overseer_id)

    date_folders = []
    if worker_id:
        result = drive_service.files().list(
            q=f"'{worker_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false",
            fields="files(id, name)"
        ).execute()
        date_folders = result.get('files', [])

    return render_template("worker_dates.html", username=username, worker_code=worker_code, folders=date_folders)

@app.route('/worker/<worker_code>/<date>')
def list_worker_screenshots(worker_code, date):
    if 'overseer_code' not in session:
        return redirect(url_for('login'))

    ocode = session['overseer_code']
    conn = sqlite3.connect('manager.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM workers WHERE overseer_code=? AND worker_code=?", (ocode, worker_code))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return "Worker not found", 404

    username = result[0]
    root_id = get_folder_id("TraceOnScreenshots")
    overseer_id = get_folder_id(ocode, parent_id=root_id)
    worker_id = get_folder_id(f"{username}-{worker_code}", parent_id=overseer_id)
    date_folder_id = get_folder_id(date, parent_id=worker_id)
    screenshots = list_screenshots(date_folder_id)

    return render_template("screenshots.html", username=username, worker_code=worker_code, date=date, screenshots=screenshots)

@app.route('/api/register_worker', methods=['POST'])
def register_worker():
    data = request.get_json()

    required_fields = ['username', 'worker_code', 'overseer_code']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "error": "Missing fields"}), 400

    username = data['username']
    worker_code = data['worker_code']
    overseer_code = data['overseer_code']

    # Connect to the manager website's DB
    conn = sqlite3.connect('manager.db')
    cursor = conn.cursor()

    # Optional: Create table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            worker_code TEXT,
            overseer_code TEXT
        )
    ''')

    # Prevent duplicates
    cursor.execute("SELECT * FROM workers WHERE worker_code=? AND overseer_code=?", (worker_code, overseer_code))
    if cursor.fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Worker already exists"}), 409

    # Insert worker
    cursor.execute("INSERT INTO workers (username, worker_code, overseer_code) VALUES (?, ?, ?)",
                   (username, worker_code, overseer_code))
    conn.commit()
    conn.close()

    return jsonify({"success": True}), 201

@app.route('/worker/<worker_code>/<date>/generate_report', methods=['POST'])
def generate_productivity_report(worker_code, date):
    if 'overseer_code' not in session:
        return redirect(url_for('login'))

    ocode = session['overseer_code']

    # Get username
    conn = sqlite3.connect('manager.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM workers WHERE overseer_code=? AND worker_code=?", (ocode, worker_code))
    result = cursor.fetchone()
    conn.close()
    if not result:
        return "Worker not found", 404
    username = result[0]

    # Get screenshot folder
    root_id = get_folder_id("TraceOnScreenshots")
    overseer_id = get_folder_id(ocode, parent_id=root_id)
    worker_id = get_folder_id(f"{username}-{worker_code}", parent_id=overseer_id)
    date_folder_id = get_folder_id(date, parent_id=worker_id)
    screenshots = list_screenshots(date_folder_id)

    if not screenshots:
        return "No screenshots found", 404

    # Download & encode images
    image_data = []
    for ss in screenshots:
        try:
            img_bytes = download_file_bytes(ss['id'])
            encoded = base64.b64encode(img_bytes).decode('utf-8')
            image_data.append(encoded)
        except Exception as e:
            print(f"Error with {ss['name']}: {e}")

    gemini_key = "Gemini-API-key"

    # Use Gemini 2.5 Flash model
    gemini_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key={gemini_key}"

    # Format content payload
    parts = [{"text": f"Analyze these screenshots taken on {date} and generate a productivity report."}]

    parts += [{
        "inlineData": {
            "mimeType": "image/jpeg",
            "data": img  # base64-encoded image string
        }
    } for img in image_data]

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": parts
            }
        ]
    }

    response = requests.post(
        gemini_url,
        json=payload,
        headers={"Content-Type": "application/json"}
    )

    if response.status_code != 200:
        return f"Gemini error: {response.text}", 500

    report_text = response.json()['candidates'][0]['content']['parts'][0]['text']

    # Generate PDF
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=A4)

    # Constants
    width, height = A4
    left_margin = 1 * inch
    right_margin = 1 * inch
    top_margin = height - 1 * inch
    bottom_margin = 1 * inch
    line_height = 16
    max_chars_per_line = 100
    current_y = top_margin

    # Title Bar
    title_height = 0.4 * inch
    c.setFillColor(colors.lightblue)
    c.rect(left_margin - 0.2 * inch, current_y, width - 2 * (left_margin - 0.2 * inch), title_height, fill=True, stroke=0)

    # Title Text
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(left_margin, current_y + 0.13 * inch, f"Productivity Report for {username} on {date}")
    current_y -= (title_height + 0.3 * inch)

    # Set font for body
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.black)

    # Process and draw report text
    for line in report_text.split('\n'):
        wrapped_lines = textwrap.wrap(line, width=max_chars_per_line)
        for wrapped_line in wrapped_lines:
            if current_y <= bottom_margin:
                c.showPage()
                c.setFont("Helvetica", 11)
                current_y = top_margin
            c.drawString(left_margin, current_y, wrapped_line)
            current_y -= line_height

        # Add a separator between paragraph chunks (optional)
        if current_y - 5 > bottom_margin:
            c.setStrokeColor(colors.lightgrey)
            c.line(left_margin, current_y + 4, width - right_margin, current_y + 4)
            current_y -= 8

    # Finalize PDF
    c.showPage()
    c.save()
    pdf_buffer.seek(0)

    return send_file(pdf_buffer, as_attachment=True,
                    download_name=f"{username}_{date}_report.pdf",
                    mimetype='application/pdf')



if __name__ == '__main__':
    init_db()
    app.run(debug=True)
