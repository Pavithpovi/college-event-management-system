from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import json
import csv
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='college_eventsystem'
    )
    return conn

def execute_query(query, params=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        if query.strip().upper().startswith('SELECT'):
            result = cursor.fetchall()
        else:
            conn.commit()
            result = cursor.lastrowid
        return result
    finally:
        cursor.close()
        conn.close()

def execute_single_query(query, params=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        if query.strip().upper().startswith('SELECT'):
            result = cursor.fetchone()
        else:
            conn.commit()
            result = cursor.lastrowid
        return result
    finally:
        cursor.close()
        conn.close()

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL,
            email VARCHAR(255) UNIQUE,
            department VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create events table
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            date DATE NOT NULL,
            time TIME NOT NULL,
            location VARCHAR(255) NOT NULL,
            capacity INT,
            category VARCHAR(100),
            status VARCHAR(50) DEFAULT 'upcoming',
            organizer_id INT,
            resources TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organizer_id) REFERENCES users (id)
        )
    ''')
    
    # Create registrations table
    c.execute('''
        CREATE TABLE IF NOT EXISTS registrations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            event_id INT,
            status VARCHAR(50) DEFAULT 'registered',
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attendance_status VARCHAR(50) DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (event_id) REFERENCES events (id)
        )
    ''')
    
    # Create resources table
    c.execute('''
        CREATE TABLE IF NOT EXISTS resources (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            quantity INT,
            event_id INT,
            status VARCHAR(50) DEFAULT 'available',
            FOREIGN KEY (event_id) REFERENCES events (id)
        )
    ''')
    
    # Create or update faculty account
    try:
        # First check if the faculty account exists
        c.execute('SELECT * FROM users WHERE username = %s', ('faculty',))
        existing_user = c.fetchone()
        
        if existing_user:
            # Update existing account to ensure correct role
            c.execute('''
                UPDATE users 
                SET role = %s, password = %s, email = %s, department = %s
                WHERE username = %s
            ''', ('faculty', generate_password_hash('faculty123'), 'faculty@college.edu', 'Administration', 'faculty'))
            print("Existing faculty account updated!")
        else:
            # Create new faculty account
            hashed_password = generate_password_hash('faculty123')
            c.execute(
                'INSERT INTO users (username, password, role, email, department) VALUES (%s, %s, %s, %s, %s)',
                ('faculty', hashed_password, 'faculty', 'faculty@college.edu', 'Administration')
            )
            print("New faculty account created!")
        
        print("Faculty login credentials:")
        print("Username: faculty")
        print("Password: faculty123")
        
    except mysql.connector.Error as e:
        print(f"Error managing faculty account: {e}")
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/faculty_login', methods=['GET', 'POST'])
def faculty_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # First check if the user exists
        user = execute_single_query('SELECT * FROM users WHERE username = %s', (username,))
        
        if not user:
            flash('Username not found', 'error')
            return render_template('faculty_login.html')
            
        # Then check if the user is faculty
        if user['role'] != 'faculty':
            flash('This account is not a faculty account', 'error')
            return render_template('faculty_login.html')
            
        # Finally check the password
        if check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password', 'error')
            return render_template('faculty_login.html')
            
    return render_template('faculty_login.html')

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = execute_single_query('SELECT * FROM users WHERE username = %s AND role = %s', 
                          (username, 'student'))
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password for student account', 'error')
    return render_template('student_login.html')

@app.route('/student_register', methods=['GET'])
def student_register():
    return render_template('student_register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        role = request.form['role']
        email = request.form.get('email', '')
        department = request.form.get('department', '')
        
        # Validate passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('student_register' if role == 'student' else 'register'))
        
        try:
            execute_query(
                'INSERT INTO users (username, password, role, email, department) VALUES (%s, %s, %s, %s, %s)',
                (username, generate_password_hash(password), role, email, department)
            )
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('student_login' if role == 'student' else 'faculty_login'))
        except mysql.connector.Error:
            flash('Username or email already exists', 'error')
            return redirect(url_for('student_register' if role == 'student' else 'register'))
    
    # If GET request, show the appropriate registration form
    if request.args.get('role') == 'student':
        return render_template('student_register.html')
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    events = execute_query('SELECT * FROM events ORDER BY date DESC')
    return render_template('dashboard.html', events=events)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session or session['role'] != 'faculty':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        date = request.form['date']
        time = request.form['time']
        location = request.form['location']
        capacity = request.form['capacity']
        category = request.form['category']
        resources = request.form.getlist('resources')
        
        try:
            event_id = execute_query(
                '''INSERT INTO events (title, description, date, time, location, capacity, 
                category, organizer_id, resources) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                (title, description, date, time, location, capacity, category, 
                session['user_id'], json.dumps(resources))
            )
            
            # Add resources
            for resource in resources:
                execute_query(
                    'INSERT INTO resources (name, event_id) VALUES (%s, %s)',
                    (resource, event_id)
                )
            
            flash('Event created successfully!', 'success')
            return redirect(url_for('event_details', event_id=event_id))
        except Exception as e:
            flash(f'Error creating event: {str(e)}', 'error')
    
    return render_template('create_event.html')

@app.route('/event/<int:event_id>')
def event_details(event_id):
    event = execute_single_query('SELECT * FROM events WHERE id = %s', (event_id,))
    
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get registration count
    registration_count = execute_single_query(
        'SELECT COUNT(*) as count FROM registrations WHERE event_id = %s', 
        (event_id,)
    )['count']
    
    # Get resources
    resources = execute_query(
        'SELECT * FROM resources WHERE event_id = %s', 
        (event_id,)
    )
    
    # Check if user is registered
    is_registered = False
    if 'user_id' in session:
        registration = execute_single_query(
            'SELECT * FROM registrations WHERE user_id = %s AND event_id = %s',
            (session['user_id'], event_id)
        )
        is_registered = bool(registration)
    
    return render_template('event_details.html', 
                         event=event, 
                         registration_count=registration_count,
                         resources=resources,
                         is_registered=is_registered)

@app.route('/register_event/<int:event_id>', methods=['POST'])
def register_event(event_id):
    if 'user_id' not in session:
        flash('Please login to register for events', 'error')
        return redirect(url_for('login'))
    
    # Check if event exists and has capacity
    event = execute_single_query('SELECT * FROM events WHERE id = %s', (event_id,))
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('dashboard'))
    
    registration_count = execute_single_query(
        'SELECT COUNT(*) as count FROM registrations WHERE event_id = %s', 
        (event_id,)
    )['count']
    
    if registration_count >= event['capacity']:
        flash('Event is full', 'error')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Check if already registered
    existing_registration = execute_single_query(
        'SELECT * FROM registrations WHERE user_id = %s AND event_id = %s',
        (session['user_id'], event_id)
    )
    
    if existing_registration:
        flash('You are already registered for this event', 'info')
    else:
        execute_query(
            'INSERT INTO registrations (user_id, event_id) VALUES (%s, %s)',
            (session['user_id'], event_id)
        )
        flash('Successfully registered for the event!', 'success')
    
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/manage_event/<int:event_id>', methods=['GET', 'POST'])
def manage_event(event_id):
    if 'user_id' not in session or session['role'] != 'faculty':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    event = execute_single_query('SELECT * FROM events WHERE id = %s', (event_id,))
    
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        date = request.form['date']
        time = request.form['time']
        location = request.form['location']
        capacity = request.form['capacity']
        category = request.form['category']
        status = request.form['status']
        
        execute_query('''
            UPDATE events 
            SET title = %s, description = %s, date = %s, time = %s, 
                location = %s, capacity = %s, category = %s, status = %s
            WHERE id = %s
        ''', (title, description, date, time, location, capacity, 
              category, status, event_id))
        flash('Event updated successfully!', 'success')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Get registrations
    registrations = execute_query('''
        SELECT r.*, u.username, u.email 
        FROM registrations r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.event_id = %s
    ''', (event_id,))
    
    return render_template('manage_event.html', event=event, registrations=registrations)

@app.route('/reports')
def reports():
    if 'user_id' not in session or session['role'] != 'faculty':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Get event statistics
    event_stats = execute_single_query('''
        SELECT 
            COUNT(*) as total_events,
            SUM(CASE WHEN status = 'upcoming' THEN 1 ELSE 0 END) as upcoming_events,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_events
        FROM events
    ''')
    
    # Get registration statistics
    registration_stats = execute_single_query('''
        SELECT 
            COUNT(*) as total_registrations,
            SUM(CASE WHEN attendance_status = 'present' THEN 1 ELSE 0 END) as present_count,
            SUM(CASE WHEN attendance_status = 'absent' THEN 1 ELSE 0 END) as absent_count
        FROM registrations
    ''')
    
    # Get popular events
    popular_events = execute_query('''
        SELECT e.*, COUNT(r.id) as registration_count
        FROM events e
        LEFT JOIN registrations r ON e.id = r.event_id
        GROUP BY e.id
        ORDER BY registration_count DESC
        LIMIT 5
    ''')
    
    # Convert Row objects to dictionaries and handle None values
    event_stats = event_stats if event_stats else {
        'total_events': 0,
        'upcoming_events': 0,
        'completed_events': 0
    }
    
    registration_stats = registration_stats if registration_stats else {
        'total_registrations': 0,
        'present_count': 0,
        'absent_count': 0
    }
    
    return render_template('reports.html',
                         event_stats=event_stats,
                         registration_stats=registration_stats,
                         popular_events=popular_events)

@app.route('/update_attendance/<int:registration_id>', methods=['POST'])
def update_attendance(registration_id):
    if 'user_id' not in session or session['role'] != 'faculty':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    data = request.get_json()
    status = data.get('status')
    
    if status not in ['present', 'absent']:
        return jsonify({'success': False, 'message': 'Invalid status'})
    
    try:
        execute_query(
            'UPDATE registrations SET attendance_status = %s WHERE id = %s',
            (status, registration_id)
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/export_events')
def export_events():
    if 'user_id' not in session or session['role'] != 'faculty':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    events = conn.execute('''
        SELECT e.*, u.username as organizer_name
        FROM events e
        LEFT JOIN users u ON e.organizer_id = u.id
    ''').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Title', 'Description', 'Date', 'Time', 'Location', 
                    'Capacity', 'Category', 'Status', 'Organizer', 'Created At'])
    
    # Write data
    for event in events:
        writer.writerow([
            event['id'],
            event['title'],
            event['description'],
            event['date'],
            event['time'],
            event['location'],
            event['capacity'],
            event['category'],
            event['status'],
            event['organizer_name'],
            event['created_at']
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'events_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/export_registrations')
def export_registrations():
    if 'user_id' not in session or session['role'] != 'faculty':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    registrations = conn.execute('''
        SELECT r.*, u.username, u.email, e.title as event_title
        FROM registrations r
        JOIN users u ON r.user_id = u.id
        JOIN events e ON r.event_id = e.id
    ''').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'User', 'Email', 'Event', 'Status', 
                    'Registration Date', 'Attendance Status'])
    
    # Write data
    for reg in registrations:
        writer.writerow([
            reg['id'],
            reg['username'],
            reg['email'],
            reg['event_title'],
            reg['status'],
            reg['registration_date'],
            reg['attendance_status']
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'registrations_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/export_attendance')
def export_attendance():
    if 'user_id' not in session or session['role'] != 'faculty':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    attendance = conn.execute('''
        SELECT e.title as event_title, 
               COUNT(r.id) as total_registrations,
               SUM(CASE WHEN r.attendance_status = 'present' THEN 1 ELSE 0 END) as present_count,
               SUM(CASE WHEN r.attendance_status = 'absent' THEN 1 ELSE 0 END) as absent_count,
               SUM(CASE WHEN r.attendance_status = 'pending' THEN 1 ELSE 0 END) as pending_count
        FROM events e
        LEFT JOIN registrations r ON e.id = r.event_id
        GROUP BY e.id
    ''').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Event', 'Total Registrations', 'Present', 'Absent', 'Pending', 'Attendance Rate'])
    
    # Write data
    for record in attendance:
        total = record['total_registrations'] or 0
        present = record['present_count'] or 0
        attendance_rate = (present / total * 100) if total > 0 else 0
        
        writer.writerow([
            record['event_title'],
            total,
            record['present_count'] or 0,
            record['absent_count'] or 0,
            record['pending_count'] or 0,
            f"{attendance_rate:.1f}%"
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'attendance_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/reset_faculty', methods=['GET'])
def reset_faculty():
    try:
        # Delete existing faculty account if it exists
        execute_query('DELETE FROM users WHERE username = %s', ('faculty',))
        
        # Create new faculty account
        hashed_password = generate_password_hash('faculty123')
        execute_query(
            'INSERT INTO users (username, password, role, email, department) VALUES (%s, %s, %s, %s, %s)',
            ('faculty', hashed_password, 'faculty', 'faculty@college.edu', 'Administration')
        )
        flash('Faculty account has been reset successfully!', 'success')
    except Exception as e:
        flash(f'Error resetting faculty account: {str(e)}', 'error')
    
    return redirect(url_for('faculty_login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 