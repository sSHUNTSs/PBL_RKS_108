from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import os, pymysql, re, traceback, logging
from werkzeug.utils import secure_filename
from vigenere import vigenere_encrypt, vigenere_decrypt, bruteforce_vigenere
from config import DATABASE_CONFIG
from io import BytesIO
from bcrypt import hashpw, gensalt, checkpw
from pymysql.cursors import DictCursor
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

DEFAULT_KEY = 'kwaogaaaiqkmaamiamumicsmuiukaeamqecwqmiuaquaimiiqcamayjiewkdkvnauqbazcocks'

app.permanent_session_lifetime = timedelta(minutes=30)

logging.basicConfig(level=logging.DEBUG)

def get_db_connection():
    return pymysql.connect(**DATABASE_CONFIG)

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(DictCursor)
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['id'] = user['id']
            session['username'] = user['username']
            session['key'] = DEFAULT_KEY 
            return redirect(url_for('dashboard'))
        else: 
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

def is_valid_password(password):
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_valid_password(password):
            return render_template(
                'signup.html',
                error="Password must be at least 8 characters, contain uppercase, lowercase, and symbols!"
            )

        hashed_password = hashpw(password.encode('utf-8'), gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, hashed_password.decode('utf-8'))
            )
            conn.commit()
            flash("Signup successful! Please login.", "success")
            return redirect(url_for('login'))
        except pymysql.IntegrityError:
            flash("Username is already registered!", "danger")
            return render_template('signup.html')
        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(DictCursor)
    current_user = session['username']
    current_user_id = session.get('id')

    cursor.execute("SELECT id, username FROM users WHERE username != %s", (session['username'],))
    users = cursor.fetchall()

    cursor.execute("SELECT sender, message FROM messages WHERE receiver = %s", (current_user,))
    received_messages = cursor.fetchall()
    
    error = None
    result = None
    downloadable = None
    bruteforce_result = None
    feature = None

    for message in received_messages:
        try:
            key = session.get('key', DEFAULT_KEY) 
            logging.debug(f"Pesan yang diterima: {message['message']}")
            decrypted_message = vigenere_decrypt(message['message'], DEFAULT_KEY)
            logging.debug(f"Pesan setelah didekripsi: {decrypted_message}")
            message['decrypted_message'] = decrypted_message
        except Exception as e:
            message['decrypted_message'] = "[Gagal mendekripsi pesan]"
            logging.error(f"Error saat mendekripsi pesan: {e}")

    if request.method == 'POST':
        feature = request.form.get('feature')
        key = request.form.get('key')
        file = request.files.get('file') 

        try:
            if feature == 'encrypt_text':
                text = request.form.get('text')
                if text and key:
                    result = vigenere_encrypt(text, key)
                    encrypted_message = result
                else:
                    error = "Text and key must be filled!"

            elif feature == 'decrypt_text':
                ciphertext = request.form.get('ciphertext')
                if ciphertext and key:
                    result = vigenere_decrypt(ciphertext, key)
                else:
                    error = "Ciphertext dan key must be filled!"
            
            if feature == 'send_message':
                recipient = request.form.get('receiver')
                message = request.form.get('message')

                if not key:
                    key = DEFAULT_KEY

                if recipient and message:
                    try: 
                        encrypted_message = vigenere_encrypt(message, DEFAULT_KEY)
                        cursor.execute(
                            "INSERT INTO messages (sender, receiver, message) VALUES (%s, %s, %s)",
                            (session['username'], recipient, encrypted_message),
                        )
                        conn.commit()
                        return redirect(url_for('dashboard'))
                    except Exception as e:
                        error = f"Failed to send message: {str(e)}"
                else:
                    error = "Receiver, and message must be filled!"

            if feature == 'bruteforce':
                ciphertext = request.form.get('ciphertext', '').strip()
                max_length = request.form.get('max_length', '3').strip()
                try:
                    max_length = int(max_length) 
                    bruteforce_result = bruteforce_vigenere(ciphertext, max_length)
                except Exception as e:
                    error = f"There is an error: {e}"
        
            elif feature == 'process_file_txt':
                if file and file.filename:
                    if not file.filename.endswith('.txt'):
                        error = "Only .txt files are supported!"
                    elif file.content_length > 1 * 1024 * 1024: 
                        error = "File too large! Maximum 1 MB."
                    else:
                        content = file.read().decode('utf-8') 
            
                        if request.form.get('operation') == 'encrypt':
                            encrypted_content = vigenere_encrypt(content, key)
                            return send_file(BytesIO(encrypted_content.encode('utf-8')),
                                            download_name=f'encrypted_{file.filename}',
                                            as_attachment=True)
                        elif request.form.get('operation') == 'decrypt':
                            decrypted_content = vigenere_decrypt(content, key)
                            return send_file(BytesIO(decrypted_content.encode('utf-8')),
                                            download_name=f'decrypted_{file.filename}',
                                            as_attachment=True)
                        else:
                            error = "Operasi tidak valid!"
                            return render_template('dashboard.html', username=session['username'], error=error, result=result,
                                                    downloadable=downloadable, received_messages=received_messages, users=users)
                else:
                    error = "File must be uploaded!" 
        except Exception as e:
            error = f"Terjadi kesalahan: {str(e)}"
    conn.close()
    return render_template('dashboard.html', username=session['username'], error=error, result=result, bruteforce_result=bruteforce_result,
                           downloadable=downloadable, received_messages=received_messages, users=users)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(DictCursor)

    try:
        receiver = request.form.get('receiver', '').strip()
        raw_message = request.form.get('message', '').strip()

        if not receiver or not raw_message:
            error = "Receiver, and message must be filled!"
            return render_template('dashboard.html', username=session['username'], error=error)

        cursor.execute("SELECT id FROM users WHERE id = %s", (receiver,))
        recipient = cursor.fetchone()
        if not recipient:
            error = "Receiver not found!"
            return render_template('dashboard.html', username=session['username'], error=error)
        
        logging.debug(f"Pesan sebelum dienkripsi: {raw_message}")
        encrypted_message = vigenere_encrypt(raw_message, DEFAULT_KEY)
        logging.debug(f"Pesan terenkripsi: {encrypted_message}")        
        
        cursor.execute(
            "INSERT INTO messages (sender, receiver, message) VALUES (%s, %s, %s)",
            (session['username'], receiver, encrypted_message)
        )
        conn.commit()

        success_message = "Message sent successfully!"
        return render_template('dashboard.html', username=session['username'], success=success_message)
    except Exception as e:
        error = f"An error occurred while sending the message: {e}"
        logging.error(f"Error to send message: {e}")
        return render_template('dashboard.html', username=session['username'], error=error)
    finally:
        conn.close()

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        receiver = request.form.get('receiver', None)
        message = request.form.get('message', None)

        if not message:
            return "Error: Message must be provided"

        decrypted_message = vigenere_decrypt(message, DEFAULT_KEY)
        return f"Receiver: {receiver}, Decrypted Message: {decrypted_message}, Key: {DEFAULT_KEY}"

    except Exception as e:
        return f"Error while decrypting: {e}"

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['RESULT_FOLDER'], filename), as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()  
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port='1000')