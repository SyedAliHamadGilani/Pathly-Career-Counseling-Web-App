import os
import re
from datetime import datetime
from functools import wraps
from flask import Flask, request, redirect, url_for, flash, render_template, render_template_string, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# -------------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------------
app = Flask(__name__)
# Security: Use environment variable or fallback
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-pathly-project')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pathly.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CV Upload Configuration
UPLOAD_FOLDER = 'static/uploads/cvs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_strong_password(password):
    # At least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(regex, password)

# -------------------------------------------------------------------------
# DATABASE MODELS
# -------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    
    student_profile = db.relationship('Student', backref='user', uselist=False)
    counselor_profile = db.relationship('Counselor', backref='user', uselist=False)
    ambassador_profile = db.relationship('Ambassador', backref='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    ssc_marks = db.Column(db.Float, default=0.0)
    hssc_marks = db.Column(db.Float, default=0.0)
    test_score = db.Column(db.Float, default=0.0)
    aggregate = db.Column(db.Float, default=0.0)
    city_pref = db.Column(db.String(100))
    degree_pref = db.Column(db.String(100))

class Counselor(db.Model):
    __tablename__ = 'counselors'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    qualification = db.Column(db.String(200))
    experience = db.Column(db.String(500))
    status = db.Column(db.String(20), default='Pending')
    cv_filename = db.Column(db.String(255))  # Added CV field

class Ambassador(db.Model):
    __tablename__ = 'ambassadors'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    university_name = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)

class University(db.Model):
    __tablename__ = 'universities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100))
    website = db.Column(db.String(200))
    min_aggregate = db.Column(db.Float, default=0.0)
    is_approved = db.Column(db.Boolean, default=False)

class MeritList(db.Model):
    __tablename__ = 'merit_lists'
    id = db.Column(db.Integer, primary_key=True)
    university_id = db.Column(db.Integer, db.ForeignKey('universities.id'))
    program_name = db.Column(db.String(200))
    year = db.Column(db.Integer)
    closing_merit = db.Column(db.Float)

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class Complaint(db.Model):
    __tablename__ = 'complaints'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    counselor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Open')

class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------------------------------------------------------
# RBAC DECORATORS
# -------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("Access Denied")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

student_required = role_required('student')
admin_required = role_required('admin')

def counselor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'counselor':
            flash("Access Denied")
            return redirect(url_for('login'))
        if current_user.counselor_profile.status != 'Approved':
            flash("Access Denied: Pending Approval")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def ambassador_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'ambassador':
            flash("Access Denied")
            return redirect(url_for('login'))
        if current_user.ambassador_profile.status != 'Approved':
            flash("Access Denied: Pending Approval")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------------

@app.route('/')
def index():
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    # Assuming index.html is in the root template folder
    return render_template('index.html', announcements=announcements)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'student': return redirect(url_for('student_dashboard'))
            elif user.role == 'counselor': return redirect(url_for('counselor_dashboard'))
            elif user.role == 'admin': return redirect(url_for('admin_dashboard'))
            elif user.role == 'ambassador': return redirect(url_for('ambassador_dashboard'))
        flash("Invalid Credentials.")
        return redirect(url_for('login'))
    # Assuming login.html is in the root template folder
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Password Strength Check
        if not is_strong_password(password):
            flash("Password too weak. Must contain 8+ chars, Uppercase, Lowercase, Number, and Special Char.")
            return redirect(url_for('register'))

        # Check Email
        if User.query.filter_by(email=email).first():
            flash("Email already exists")
            return redirect(url_for('register'))
        
        # Check Username (FIX for IntegrityError)
        if User.query.filter_by(username=username).first():
            flash("Username already taken. Please choose a different one.")
            return redirect(url_for('register'))

        # Handle CV Upload for Counselors
        cv_filename = None
        if role == 'counselor':
            if 'cv' not in request.files:
                flash('No CV uploaded for counselor registration.')
                return redirect(url_for('register'))
            file = request.files['cv']
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('register'))
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{username}_{int(datetime.now().timestamp())}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cv_filename = filename
            else:
                flash('Invalid file type. Only PDF/DOC allowed.')
                return redirect(url_for('register'))

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        if role == 'student':
            db.session.add(Student(id=new_user.id))
        elif role == 'counselor':
            db.session.add(Counselor(id=new_user.id, status='Pending', cv_filename=cv_filename))
        elif role == 'ambassador':
            db.session.add(Ambassador(id=new_user.id, status='Pending'))
        
        db.session.commit()
        flash("Registration Successful.")
        return redirect(url_for('login'))
    # Assuming register.html is in the root template folder
    return render_template('register.html')

# STUDENT ROUTES
@app.route('/student/dashboard')
@login_required
@student_required
def student_dashboard():
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(3).all()
    return render_template('student/student_dashboard.html', announcements=announcements)

@app.route('/student/aggregate', methods=['GET', 'POST'])
@login_required
@student_required
def calculate_aggregate():
    student = current_user.student_profile
    if request.method == 'POST':
        try:
            ssc = float(request.form.get('ssc'))
            hssc = float(request.form.get('hssc'))
            test = float(request.form.get('test'))
            formula = request.form.get('formula')

            if formula == 'engineering':
                agg = (ssc * 0.1) + (hssc * 0.4) + (test * 0.5)
            elif formula == 'medical':
                agg = (ssc * 0.1) + (hssc * 0.4) + (test * 0.5)
            else:
                agg = (ssc * 0.2) + (hssc * 0.8)

            student.ssc_marks = ssc
            student.hssc_marks = hssc
            student.test_score = test
            student.aggregate = agg
            db.session.commit()
            flash(f"Aggregate Calculated: {agg:.2f}%")
        except ValueError:
            flash("Invalid input.")
    return render_template('student/student_aggregate.html')

@app.route('/student/suggestions')
@login_required
@student_required
def student_suggestions():
    pref_city = current_user.student_profile.city_pref
    user_agg = current_user.student_profile.aggregate
    
    query = University.query.filter_by(is_approved=True)
    if pref_city:
        query = query.filter_by(city=pref_city)
    
    all_unis = query.all()
    suggested_unis = [u for u in all_unis if user_agg >= u.min_aggregate]
    
    return render_template('student/student_suggestions.html', suggestions=suggested_unis, user_agg=user_agg)

@app.route('/student/chat', defaults={'counselor_id': None}, methods=['GET', 'POST'])
@app.route('/student/chat/<int:counselor_id>', methods=['GET', 'POST'])
@login_required
@student_required
def student_chat(counselor_id):
    if request.method == 'POST':
        if not counselor_id:
            flash("Select a counselor first.")
            return redirect(url_for('student_chat'))
        
        msg_text = request.form.get('message')
        if msg_text:
            new_msg = ChatMessage(sender_id=current_user.id, receiver_id=counselor_id, message=msg_text)
            db.session.add(new_msg)
            db.session.commit()
        return redirect(url_for('student_chat', counselor_id=counselor_id))

    counselors = Counselor.query.filter_by(status='Approved').all()
    
    messages = []
    active_counselor = None
    if counselor_id:
        active_counselor = User.query.get(counselor_id)
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == counselor_id)) |
            ((ChatMessage.sender_id == counselor_id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.timestamp).all()

    return render_template('student/student_chat.html', 
                           counselors=counselors, 
                           messages=messages, 
                           active_counselor=active_counselor)

@app.route('/student/preferences', methods=['GET', 'POST'])
@login_required
@student_required
def student_preferences():
    if request.method == 'POST':
        current_user.student_profile.city_pref = request.form.get('city')
        current_user.student_profile.degree_pref = request.form.get('degree')
        db.session.commit()
        flash("Preferences Updated")
    return render_template('student/student_preferences.html')

@app.route('/student/complaint', methods=['POST'])
@login_required
@student_required
def file_complaint():
    counselor_id = request.form.get('counselor_id')
    desc = request.form.get('description')
    if counselor_id and desc:
        complaint = Complaint(student_id=current_user.id, counselor_id=counselor_id, description=desc)
        db.session.add(complaint)
        db.session.commit()
        flash("Complaint Filed")
    return redirect(url_for('student_chat', counselor_id=counselor_id))

@app.route('/student/merit_lists')
@login_required
@student_required
def view_merit_lists():
    lists = MeritList.query.all()
    count = len(lists)
    return render_template_string("""
        {% extends "base.html" %}
        {% block content %}
        <div class="dashboard-header">
            <h1>Merit Lists</h1>
            <a href="{{ url_for('student_dashboard') }}">&larr; Back to Dashboard</a>
        </div>
        <div class="card">
            <h3>Historical Merit Lists</h3>
            <p>Displaying {{ count }} lists.</p>
            <p class="text-grey">Detailed list view coming soon.</p>
        </div>
        {% endblock %}
    """, count=count)

# COUNSELOR ROUTES
@app.route('/counselor/dashboard')
@login_required
@counselor_required
def counselor_dashboard():
    return render_template('counselor/counselor_dashboard.html')

@app.route('/counselor/chat', defaults={'student_id': None}, methods=['GET', 'POST'])
@app.route('/counselor/chat/<int:student_id>', methods=['GET', 'POST'])
@login_required
@counselor_required
def counselor_view_messages(student_id):
    if request.method == 'POST':
        if not student_id:
            return redirect(url_for('counselor_view_messages'))
        msg_text = request.form.get('message')
        if msg_text:
            new_msg = ChatMessage(sender_id=current_user.id, receiver_id=student_id, message=msg_text)
            db.session.add(new_msg)
            db.session.commit()
        return redirect(url_for('counselor_view_messages', student_id=student_id))

    all_msgs = ChatMessage.query.filter(
        (ChatMessage.receiver_id == current_user.id) | (ChatMessage.sender_id == current_user.id)
    ).all()
    
    contact_ids = set()
    for m in all_msgs:
        if m.sender_id != current_user.id: contact_ids.add(m.sender_id)
        if m.receiver_id != current_user.id: contact_ids.add(m.receiver_id)
    
    students_list = User.query.filter(User.id.in_(contact_ids)).all()

    messages = []
    active_student = None
    if student_id:
        active_student = User.query.get(student_id)
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == student_id)) |
            ((ChatMessage.sender_id == student_id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.timestamp).all()

    return render_template('counselor/counselor_chat.html', 
                           students=students_list, 
                           messages=messages, 
                           active_student=active_student)

# ADMIN ROUTES
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    pending_counselors = Counselor.query.filter_by(status='Pending').count()
    pending_ambassadors = Ambassador.query.filter_by(status='Pending').count()
    pending_unis = University.query.filter_by(is_approved=False).count()
    return render_template('admin/admin_dashboard.html', 
                           pending_counselors=pending_counselors, 
                           pending_ambassadors=pending_ambassadors, 
                           pending_unis=pending_unis)

@app.route('/admin/pending_details')
@login_required
@admin_required
def view_pending_details():
    pending_counselors = Counselor.query.filter_by(status='Pending').all()
    pending_ambassadors = Ambassador.query.filter_by(status='Pending').all()
    return render_template('admin/pending_list.html', 
                           counselors=pending_counselors, 
                           ambassadors=pending_ambassadors)

@app.route('/download_cv/<filename>')
@login_required
@admin_required
def download_cv(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/approve_counselor/<int:counselor_id>/<action>')
@login_required
@admin_required
def approve_counselor(counselor_id, action):
    counselor = Counselor.query.get(counselor_id)
    if counselor:
        counselor.status = 'Approved' if action == 'approve' else 'Rejected'
        db.session.commit()
        flash(f"Counselor {action}d.")
    return redirect(url_for('view_pending_details'))

@app.route('/admin/approve_ambassador/<int:ambassador_id>/<action>')
@login_required
@admin_required
def approve_ambassador(ambassador_id, action):
    ambassador = Ambassador.query.get(ambassador_id)
    if ambassador:
        ambassador.status = 'Approved' if action == 'approve' else 'Rejected'
        db.session.commit()
        flash(f"Ambassador {action}d.")
    return redirect(url_for('view_pending_details'))

@app.route('/admin/approve_university/<int:uni_id>/<action>')
@login_required
@admin_required
def approve_university(uni_id, action):
    uni = University.query.get(uni_id)
    if uni:
        if action == 'approve':
            uni.is_approved = True
            db.session.commit()
        elif action == 'reject':
            db.session.delete(uni)
            db.session.commit()
        flash(f"University request processed.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/announcement', methods=['POST'])
@login_required
@admin_required
def post_announcement():
    title = request.form.get('title')
    content = request.form.get('content')
    if title and content:
        db.session.add(Announcement(title=title, content=content))
        db.session.commit()
        flash("Announcement Posted")
    return redirect(url_for('admin_dashboard'))

# AMBASSADOR ROUTES
@app.route('/ambassador/dashboard')
@login_required
@ambassador_required
def ambassador_dashboard():
    return render_template('ambassador/ambassador_dashboard.html')

@app.route('/ambassador/add_university', methods=['GET', 'POST'])
@login_required
@ambassador_required
def add_university():
    if request.method == 'POST':
        name = request.form.get('name')
        city = request.form.get('city')
        uni = University(name=name, city=city, min_aggregate=60.0, is_approved=False)
        db.session.add(uni)
        db.session.commit()
        flash("University submitted.")
        return redirect(url_for('ambassador_dashboard'))
    return render_template('ambassador/add_university.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create Default Admin
        if not User.query.filter_by(role='admin').first():
            admin = User(username='admin', email='admin@pathly.com', role='admin')
            admin.set_password('Admin@1234')
            db.session.add(admin)
            db.session.commit()
            db.session.add(Admin(id=admin.id))
            db.session.commit()
    app.run(debug=True)