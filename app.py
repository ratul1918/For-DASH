from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import json
import requests
from geopy.distance import geodesic
import folium
from folium import plugins
import openai

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dash-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dash.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")

# OpenAI API Key (you'll need to set this in your environment)
openai.api_key = os.getenv('OPENAI_API_KEY', 'your-openai-api-key-here')

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'user', 'admin', 'rescue_team'
    phone = db.Column(db.String(20))
    location_lat = db.Column(db.Float)
    location_lng = db.Column(db.Float)
    is_online = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Help Request Model
class HelpRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)  # food, shelter, water, medical, evacuation
    description = db.Column(db.Text)
    urgency_level = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    location_lat = db.Column(db.Float, nullable=False)
    location_lng = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('help_requests', lazy=True))

# Resource Offer Model
class ResourceOffer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # shelter, food, transport, supplies
    description = db.Column(db.Text)
    quantity = db.Column(db.String(100))
    location_lat = db.Column(db.Float, nullable=False)
    location_lng = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('resource_offers', lazy=True))

# SOS Alert Model
class SOSAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_lat = db.Column(db.Float, nullable=False)
    location_lng = db.Column(db.Float, nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')  # active, responded, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('sos_alerts', lazy=True))

# Chat Message Model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    room_id = db.Column(db.String(100), nullable=False)  # For group chats or SOS rooms
    message = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')  # text, location, resource
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_messages', lazy=True))

# Bulletin Post Model
class BulletinPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_type = db.Column(db.String(50), nullable=False)  # announcement, warning, instruction, update
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    is_pinned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    author = db.relationship('User', backref=db.backref('bulletin_posts', lazy=True))

# Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)  # weather, roadblock, medical_camp, sos, etc.
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.is_online = True
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        phone = request.form.get('phone', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')
        
        user = User(username=username, email=email, user_type=user_type, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.user_type == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.user_type == 'rescue_team':
        return redirect(url_for('rescue_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.user_type != 'user':
        return redirect(url_for('dashboard'))
    
    # Get recent help requests
    help_requests = HelpRequest.query.filter_by(user_id=current_user.id).order_by(HelpRequest.created_at.desc()).limit(5).all()
    
    # Get recent notifications
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Get recent bulletin posts
    bulletin_posts = BulletinPost.query.order_by(BulletinPost.created_at.desc()).limit(5).all()
    
    return render_template('user_dashboard.html', 
                         help_requests=help_requests,
                         notifications=notifications,
                         bulletin_posts=bulletin_posts)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    # Analytics data
    total_users = User.query.count()
    active_sos = SOSAlert.query.filter_by(status='active').count()
    pending_requests = HelpRequest.query.filter_by(status='pending').count()
    available_resources = ResourceOffer.query.filter_by(is_available=True).count()
    
    # Recent activity
    recent_sos = SOSAlert.query.order_by(SOSAlert.created_at.desc()).limit(10).all()
    recent_requests = HelpRequest.query.order_by(HelpRequest.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         active_sos=active_sos,
                         pending_requests=pending_requests,
                         available_resources=available_resources,
                         recent_sos=recent_sos,
                         recent_requests=recent_requests)

@app.route('/rescue_dashboard')
@login_required
def rescue_dashboard():
    if current_user.user_type != 'rescue_team':
        return redirect(url_for('dashboard'))
    
    # Get active SOS alerts
    active_sos = SOSAlert.query.filter_by(status='active').order_by(SOSAlert.created_at.desc()).all()
    
    # Get high priority help requests
    urgent_requests = HelpRequest.query.filter(
        HelpRequest.urgency_level.in_(['high', 'critical']),
        HelpRequest.status == 'pending'
    ).order_by(HelpRequest.created_at.desc()).all()
    
    return render_template('rescue_dashboard.html',
                         active_sos=active_sos,
                         urgent_requests=urgent_requests)

# API Routes

# Socket.IO Events
@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        if current_user.user_type == 'rescue_team':
            join_room('rescue_teams')
        emit('connected', {'user_id': current_user.id, 'username': current_user.username})

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        if current_user.user_type == 'rescue_team':
            leave_room('rescue_teams')

@socketio.on('join_chat')
def on_join_chat(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{current_user.username} joined the chat'}, room=room)

@socketio.on('leave_chat')
def on_leave_chat(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{current_user.username} left the chat'}, room=room)

@socketio.on('send_message')
def on_send_message(data):
    room = data['room']
    message = data['message']
    
    # Save message to database
    chat_message = ChatMessage(
        sender_id=current_user.id,
        room_id=room,
        message=message
    )
    db.session.add(chat_message)
    db.session.commit()
    
    emit('new_message', {
        'id': chat_message.id,
        'sender': current_user.username,
        'message': message,
        'timestamp': chat_message.created_at.isoformat()
    }, room=room)

# AI Chat Assistant
@app.route('/api/ai_chat', methods=['POST'])
@login_required
def ai_chat():
    data = request.get_json()
    user_message = data.get('message', '')
    
    # Simple AI responses for emergency queries
    emergency_keywords = ['emergency', 'help', 'sos', 'danger', 'fire', 'flood', 'earthquake', 'medical']
    
    if any(keyword in user_message.lower() for keyword in emergency_keywords):
        response = "This appears to be an emergency. Please use the SOS button immediately or call emergency services. For immediate help, use the SOS feature in the app."
    else:
        response = "I'm here to help with disaster assistance information. How can I assist you today?"
    
    return jsonify({'response': response})

# Bulletin Board Route
@app.route('/bulletin')
@login_required
def bulletin_board():
    posts = BulletinPost.query.order_by(BulletinPost.created_at.desc()).all()
    return render_template('bulletin_board.html', posts=posts)

# All Requests Route for Rescue Teams
@app.route('/all_requests')
@login_required
def all_requests():
    if current_user.user_type != 'rescue_team':
        return redirect(url_for('dashboard'))
    
    # Get all help requests
    all_help_requests = HelpRequest.query.order_by(HelpRequest.created_at.desc()).all()
    
    return render_template('all_requests.html', requests=all_help_requests)


# Send Notification Route
@app.route('/api/send_notification', methods=['POST'])
@login_required
def send_notification():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    target = data.get('target', 'all')
    
    # Determine target users
    if target == 'all':
        users = User.query.all()
    elif target == 'users':
        users = User.query.filter_by(user_type='user').all()
    elif target == 'rescue_teams':
        users = User.query.filter_by(user_type='rescue_team').all()
    else:
        users = User.query.all()
    
    # Create notifications for all target users
    for user in users:
        notification = Notification(
            user_id=user.id,
            title=data.get('title'),
            message=data.get('message'),
            notification_type=data.get('notification_type')
        )
        db.session.add(notification)
    
    db.session.commit()
    
    # Send real-time notification to all target users
    socketio.emit('new_notification', {
        'title': data.get('title'),
        'message': data.get('message'),
        'notification_type': data.get('notification_type'),
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({'status': 'success'})

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.is_online = True
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        phone = request.form.get('phone', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')
        
        user = User(username=username, email=email, user_type=user_type, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.user_type == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.user_type == 'rescue_team':
        return redirect(url_for('rescue_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.user_type != 'user':
        return redirect(url_for('dashboard'))
    
    # Get recent help requests
    help_requests = HelpRequest.query.filter_by(user_id=current_user.id).order_by(HelpRequest.created_at.desc()).limit(5).all()
    
    # Get recent notifications
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Get recent bulletin posts
    bulletin_posts = BulletinPost.query.order_by(BulletinPost.created_at.desc()).limit(5).all()
    
    return render_template('user_dashboard.html', 
                         help_requests=help_requests,
                         notifications=notifications,
                         bulletin_posts=bulletin_posts)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    # Analytics data
    total_users = User.query.count()
    active_sos = SOSAlert.query.filter_by(status='active').count()
    pending_requests = HelpRequest.query.filter_by(status='pending').count()
    available_resources = ResourceOffer.query.filter_by(is_available=True).count()
    
    # Recent activity
    recent_sos = SOSAlert.query.order_by(SOSAlert.created_at.desc()).limit(10).all()
    recent_requests = HelpRequest.query.order_by(HelpRequest.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         active_sos=active_sos,
                         pending_requests=pending_requests,
                         available_resources=available_resources,
                         recent_sos=recent_sos,
                         recent_requests=recent_requests)

@app.route('/rescue_dashboard')
@login_required
def rescue_dashboard():
    if current_user.user_type != 'rescue_team':
        return redirect(url_for('dashboard'))
    
    # Get active SOS alerts
    active_sos = SOSAlert.query.filter_by(status='active').order_by(SOSAlert.created_at.desc()).all()
    
    # Get high priority help requests
    urgent_requests = HelpRequest.query.filter(
        HelpRequest.urgency_level.in_(['high', 'critical']),
        HelpRequest.status == 'pending'
    ).order_by(HelpRequest.created_at.desc()).all()
    
    return render_template('rescue_dashboard.html',
                         active_sos=active_sos,
                         urgent_requests=urgent_requests)

# API Routes

# Socket.IO Events
@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        if current_user.user_type == 'rescue_team':
            join_room('rescue_teams')
        emit('connected', {'user_id': current_user.id, 'username': current_user.username})

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        if current_user.user_type == 'rescue_team':
            leave_room('rescue_teams')

@socketio.on('join_chat')
def on_join_chat(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{current_user.username} joined the chat'}, room=room)

@socketio.on('leave_chat')
def on_leave_chat(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{current_user.username} left the chat'}, room=room)

@socketio.on('send_message')
def on_send_message(data):
    room = data['room']
    message = data['message']
    
    # Save message to database
    chat_message = ChatMessage(
        sender_id=current_user.id,
        room_id=room,
        message=message
    )
    db.session.add(chat_message)
    db.session.commit()
    
    emit('new_message', {
        'id': chat_message.id,
        'sender': current_user.username,
        'message': message,
        'timestamp': chat_message.created_at.isoformat()
    }, room=room)

# AI Chat Assistant
@app.route('/api/ai_chat', methods=['POST'])
@login_required
def ai_chat():
    data = request.get_json()
    user_message = data.get('message', '')
    
    # Simple AI responses for emergency queries
    emergency_keywords = ['emergency', 'help', 'sos', 'danger', 'fire', 'flood', 'earthquake', 'medical']
    
    if any(keyword in user_message.lower() for keyword in emergency_keywords):
        response = "This appears to be an emergency. Please use the SOS button immediately or call emergency services. For immediate help, use the SOS feature in the app."
    else:
        response = "I'm here to help with disaster assistance information. How can I assist you today?"
    
    return jsonify({'response': response})

# Bulletin Board Route
@app.route('/bulletin')
@login_required
def bulletin_board():
    posts = BulletinPost.query.order_by(BulletinPost.created_at.desc()).all()
    return render_template('bulletin_board.html', posts=posts)

# All Requests Route for Rescue Teams
@app.route('/all_requests')
@login_required
def all_requests():
    if current_user.user_type != 'rescue_team':
        return redirect(url_for('dashboard'))
    
    # Get all help requests
    all_help_requests = HelpRequest.query.order_by(HelpRequest.created_at.desc()).all()
    
    return render_template('all_requests.html', requests=all_help_requests)


# Send Notification Route
@app.route('/api/send_notification', methods=['POST'])
@login_required
def send_notification():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    target = data.get('target', 'all')
    
    # Determine target users
    if target == 'all':
        users = User.query.all()
    elif target == 'users':
        users = User.query.filter_by(user_type='user').all()
    elif target == 'rescue_teams':
        users = User.query.filter_by(user_type='rescue_team').all()
    else:
        users = User.query.all()
    
    # Create notifications for all target users
    for user in users:
        notification = Notification(
            user_id=user.id,
            title=data.get('title'),
            message=data.get('message'),
            notification_type=data.get('notification_type')
        )
        db.session.add(notification)
    
    db.session.commit()
    
    # Send real-time notification to all target users
    socketio.emit('new_notification', {
        'title': data.get('title'),
        'message': data.get('message'),
        'notification_type': data.get('notification_type'),
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({'status': 'success'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create demo accounts if they don't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@dash.com', user_type='admin')
            admin.set_password('admin123')
            db.session.add(admin)
        
        if not User.query.filter_by(username='user1').first():
            user1 = User(username='user1', email='user1@dash.com', user_type='user', phone='+1234567890')
            user1.set_password('user123')
            db.session.add(user1)
        
        if not User.query.filter_by(username='rescue1').first():
            rescue1 = User(username='rescue1', email='rescue1@dash.com', user_type='rescue_team', phone='+1234567891')
            rescue1.set_password('rescue123')
            db.session.add(rescue1)
        
        db.session.commit()
        print("Demo accounts created:")
        print("Admin: username=admin, password=admin123")
        print("User: username=user1, password=user123")
        print("Rescue Team: username=rescue1, password=rescue123")
    
    socketio.run(app, debug=True, host='localhost', port=5500)
