# Import necessary modules
from flask import Flask, request, render_template, send_file, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import pytesseract
import cv2
import numpy as np
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from collections import Counter
import os
import re
from sqlalchemy.sql import func
# Initialize app and database
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Define User and Record models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    records = db.relationship('Record', backref='user', lazy=True)
    is_active = db.Column(db.Boolean, default=True)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    file_name = db.Column(db.String(300), nullable=False)
    errors = db.Column(db.Integer, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False, default='')

def ocr_core(file_path):
    """Extract text from image using Tesseract."""
    text = pytesseract.image_to_string(Image.open(file_path), lang='fra')
    return text

def detect_red_color(file_path):
    """Detect the presence of red color in the image using OpenCV."""
    image = cv2.imread(file_path)
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
    
    lower_red1 = np.array([0, 100, 100])
    upper_red1 = np.array([10, 255, 255])
    lower_red2 = np.array([160, 100, 100])
    upper_red2 = np.array([180, 255, 255])
    
    mask1 = cv2.inRange(hsv, lower_red1, upper_red1)
    mask2 = cv2.inRange(hsv, lower_red2, upper_red2)
    mask = mask1 + mask2
    
    return cv2.countNonZero(mask) > 0

def verify_document(text, file_path):
    """Verify document norms for French text."""
    results = []

    upper_direction_index = text.find("DIRECTION")
    lower_direction_index = text.find("Direction", upper_direction_index + 1)

    if upper_direction_index != -1:
        if 'ali b' in text[upper_direction_index:lower_direction_index].lower():
            results.append("ali_b_present:Ali B is present in the first DIRECTION.")
        else:
            results.append("ali_b_missing:Ali B is missing in the first DIRECTION.")
    else:
        results.append("ali_b_missing:First DIRECTION is missing.")

    if lower_direction_index != -1:
        if 'ali b' in text[lower_direction_index:].lower():
            results.append("ali_b_present:Ali B is present in the second Direction.")
        else:
            results.append("ali_b_missing:Ali B is missing in the second Direction.")
    else:
        results.append("ali_b_missing:Second Direction is missing.")

    if 'mehdi' in text.lower():
        results.append("mehdi_present:Mehdi is present in JOURNAL.")
    else:
        results.append("mehdi_missing:Mehdi is missing in JOURNAL.")

    if re.search(r'\b(?:n°|n[°o])\s*dr[1-8]/sa/\d{4}\b', text.lower()):
        results.append("num_format_present:N° format is present.")
    else:
        results.append("num_format_missing:N° format is missing.")

    if re.search(r'objet:.*\d+', text.lower()):
        results.append("objet_numbers_present:Objet numbers are present.")
    else:
        results.append("objet_numbers_missing:Objet numbers are missing.")

    if re.search(r'relatif à.*la fourniture de matériel informatique', text.lower()):
        results.append("relatif_fourniture_present:Relatif à la fourniture de matériel informatique is present.")
    else:
        results.append("relatif_fourniture_missing:Relatif à la fourniture de matériel informatique is missing.")

    if re.search(r'\b(0[1-9]|[12][0-9]|3[01])/(0[1-9]|1[0-2])/\d{4}\b', text):
        results.append("date_present:Valid date is present.")
    else:
        results.append("date_missing:Valid date is missing.")

    if 'agadir 80000' in text.lower():
        results.append("address_present:Address is present.")
    else:
        results.append("address_missing:Address is missing.")
    
    if detect_red_color(file_path):
        results.append("red_color_present:Signature is present.")
    else:
        results.append("red_color_missing:Signature is missing.")

    return results, text

@app.route('/')
def home():
    return render_template('login.html')

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Record': Record}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')

            if username == 'Admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        
        flash('Incorrect username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['username'] == 'Admin':
        users = User.query.all()
        total_users = User.query.count()

        # Calculate number of records each user has uploaded
        user_records = db.session.query(
            Record.user_id,
            func.count(Record.id).label('usage_count')
        ).group_by(Record.user_id).all()

        usage_counts = {user_id: count for user_id, count in user_records}

        # Prepare data for charts
        usernames = [user.username for user in users]
        usage_counts_list = [usage_counts.get(user.id, 0) for user in users]
        active_count = sum(1 for user in users if user.is_active)
        inactive_count = total_users - active_count

        # Example data for yearly activity
        yearly_labels = ["January", "February", "March"]  # Example labels
        yearly_counts = [10, 20, 30]  # Example counts

        return render_template('admin_dashboard.html', users=users, total_users=total_users, 
                               usage_counts=usage_counts, usernames=usernames, 
                               usage_counts_list=usage_counts_list, 
                               active_count=active_count, inactive_count=inactive_count,
                               yearly_labels=yearly_labels, yearly_counts=yearly_counts)
    flash('Access denied.', 'danger')
    return redirect(url_for('login'))



@app.route('/admin/user/<int:user_id>/toggle_active', methods=['POST'])
def toggle_user_active(user_id):
    if 'username' in session and session['username'] == 'Admin':
        user = User.query.get(user_id)
        if user:
            user.is_active = not user.is_active
            db.session.commit()
            flash('User status updated.', 'success')
        else:
            flash('User not found.', 'danger')
    else:
        flash('Access denied.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    if 'username' in session and session['username'] == 'Admin':
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted.', 'success')
        else:
            flash('User not found.', 'danger')
    else:
        flash('Access denied.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

def get_dr_region(text):
    """Return the DR region based on the text."""
    match = re.search(r'dr[1-8]', text.lower())
    if match:
        dr_number = match.group().upper()
        regions = {
            "DR1": "DR Du SUD - AGADIR",
            "DR2": "DR DE TENSIFT - MARRAKECH",
            "DR3": "DR DU CENTRE - KHOURIBGA",
            "DR4": "DR DE L'OUEST",
            "DR5": "DR DU CENTRE NORD - FES",
            "DR6": "DR DE L'ORIENTAL - OUJDA",
            "DR7": "DR CENTRE SUD - MEKNES",
            "DR8": "DR DES PROVINCES SAHARIENNES",
        }
        return regions.get(dr_number, "Unknown")
    return "Unknown"

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    error_filter = request.args.get('error_filter')
    dr_filter = request.args.get('dr_filter')
    date_filter = request.args.get('date_filter')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)

    records_query = Record.query.filter_by(user_id=session['user_id'])

    if error_filter:
        records_query = records_query.filter(Record.errors == int(error_filter))
    if dr_filter:
        dr_filter_pattern = f"%{dr_filter}%"
        records_query = records_query.filter(Record.text.ilike(dr_filter_pattern))
    if date_filter:
        records_query = records_query.filter(db.func.date(Record.date_posted) == date_filter)

    # Calculate totals before pagination
    all_records = records_query.all()
    total_errors = sum(record.errors for record in all_records)
    total_verifications = len(all_records)

    # Paginate the filtered records
    pagination = records_query.paginate(page=page, per_page=per_page)
    records = pagination.items

    for record in records:
        record.dr_region = get_dr_region(record.text)

    # Prepare data for charts
    error_dates = [record.date_posted.strftime('%Y-%m-%d') for record in all_records]
    error_counts = Counter(error_dates).values()

    dr_regions = [get_dr_region(record.text) for record in all_records]
    dr_counts = Counter(dr_regions).values()

    return render_template('dashboard.html', records=records, total_errors=total_errors, 
                           total_verifications=total_verifications, pagination=pagination, 
                           per_page=per_page, error_dates=list(Counter(error_dates).keys()), 
                           error_counts=list(error_counts), dr_regions=list(Counter(dr_regions).keys()), 
                           dr_counts=list(dr_counts))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            text = ocr_core(file_path)
            verification_results, updated_text = verify_document(text, file_path)

            errors_count = sum('missing' in result for result in verification_results)
            new_record = Record(
                username=session['username'],
                file_name=filename,
                errors=errors_count,
                user_id=session['user_id'],
                text=text
            )
            db.session.add(new_record)
            db.session.commit()

            return render_template('index.html', text=updated_text, results=verification_results, file_name=filename)

    return render_template('index.html', text=None, results=None, file_name=None)

@app.route('/download-report', methods=['POST'])
def download_report():
    results = request.form.get('results')
    if results:
        results = results.split(',')

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    elements.append(Paragraph("Document Verification Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Dear Operations Control Manager,", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("We found some issues with the provided document:", styles['Normal']))
    elements.append(Spacer(1, 12))

    data = [["Verification Item", "Result"]]
    for result in results:
        description, detail = get_result_description(result)
        data.append([description, detail])

    table = Table(data, colWidths=[180, 350])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Please review the above-mentioned issues and provide a corrected document.", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Thank you for your attention to this matter.", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Sincerely,", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("The Document Verification Team", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='verification_report.pdf', mimetype='application/pdf')

def get_result_description(result):
    if 'ali_b_present' in result:
        return "Ali B in First DIRECTION", "The text 'Ali B' was correctly found in the first instance of 'DIRECTION'."
    elif 'ali_b_missing' in result:
        return "Ali B in First DIRECTION", "The text 'Ali B' was not found in the first instance of 'DIRECTION'."
    elif 'mehdi_present' in result:
        return "Mehdi Presence", "The name 'Mehdi' is present in the document."
    elif 'mehdi_missing' in result:
        return "Mehdi Presence", "The name 'Mehdi' is missing from the document."
    elif 'num_format_present' in result:
        return "N° Format", "The document contains the correct 'N°' format with a valid year."
    elif 'num_format_missing' in result:
        return "N° Format", "The document does not contain the correct 'N°' format with a valid year."
    elif 'objet_numbers_present' in result:
        return "Objet Numbers", "The 'Objet' section contains the required numerical values."
    elif 'objet_numbers_missing' in result:
        return "Objet Numbers", "The 'Objet' section lacks the required numerical values."
    elif 'relatif_fourniture_present' in result:
        return "Relatif à la Fourniture", "'Relatif à la fourniture de matériel informatique' is correct."
    elif 'relatif_fourniture_missing' in result:
        return "Relatif à la Fourniture", "'Relatif à la fourniture de matériel informatique' is missing."
    elif 'date_present' in result:
        return "Date", "The document contains a valid date."
    elif 'date_missing' in result:
        return "Date", "The document is missing a valid date, which may imply a dating error."
    elif 'address_present' in result:
        return "Address", "The address is correctly present in the document."
    elif 'address_missing' in result:
        return "Address", "The address is missing from the document."
    elif 'red_color_present' in result:
        return "Signature", "Is present in the document."
    elif 'red_color_missing' in result:
        return "Signature", "Is missing from the document, suggesting a possible signature omission."
    else:
        return "Unknown Issue", result

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
