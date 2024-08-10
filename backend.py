from flask import Flask, request, render_template, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from uuid import uuid4
import os
import signal
import time
import subprocess
from flask_migrate import Migrate
from models import InstructorRequest
import sqlalchemy
app = Flask(__name__)
import secrets

app.secret_key = secrets.token_hex(24)
print("______________",app.secret_key)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are secure if using HTTPS

db = SQLAlchemy(app)
migrate = Migrate(app, db)

from flask import Flask, request, render_template, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from uuid import uuid4
import os
import signal
import time
import subprocess
from flask_migrate import Migrate
from models import InstructorRequest

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    instructor_id = db.Column(db.String(36), unique=True)
    simulations = db.relationship('Simulation', backref='user', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), nullable=False, unique=True)
    users = db.relationship('User', backref='role', lazy=True)

class Simulation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    simulation_id = db.Column(db.Integer, db.ForeignKey('simulation.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class PCAP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    simulation_id = db.Column(db.Integer, db.ForeignKey('simulation.id'), nullable=False)
    file_path = db.Column(db.String(100), nullable=False)
    generated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Attack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    simulation_id = db.Column(db.Integer, db.ForeignKey('simulation.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    parameters = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    members = db.relationship('GroupMember', backref='group', lazy=True)

class GroupMember(db.Model):
    __tablename__ = 'group_member'
    __table_args__ = {'extend_existing': True}
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    user = db.relationship('User', backref='group_memberships')

# The rest of your routes and functions go here...


# @app.route('/home')
# def home():
#     return render_template('home.html')

@app.route('/', methods=['GET'])
def index():
    if 'logged_in' in session:
        simulations = Simulation.query.filter_by(user_id=session['user_id']).all()
        user_role = session.get('role', 'Guest')  # Fetch user role from session
        return render_template('home.html', simulations=simulations, logged_in=True, user_role=user_role)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role.role_name
            
            print("Session Data:", session)  # Debug line
            flash('You have been logged in!', 'success')
            return redirect(url_for('index'))  # Ensure 'home' is the correct route
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html')

@app.route('/attack')
def attack():
    user_role = session.get('role', 'Guest')

    return render_template('attack.html',logged_in=True,user_role=user_role)
@app.route('/myattacks')
def myattacks():
    user_role = session.get('role', 'Guest')
    return render_template('myattacks.html', logged_in=True,user_role=user_role)

# @app.route('/creategroup', methods=['GET', 'POST'])
# def creategroup():
#     if 'logged_in' not in session or session.get('role') != 'Instructor':
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         group_name = request.form.get('groupName')  # Ensure the name matches the form field
#         if group_name:
#             new_group = Group(name=group_name)
#             db.session.add(new_group)
#             db.session.commit()
#             flash('Group created successfully!', 'success')
#             return redirect(url_for('creategroup'))

#     # Fetch all groups to display in the template
#     groups = Group.query.all()
#     return render_template('creategroup.html', groups=groups, logged_in=True, user_role=session.get('role'))
@app.route('/creategroup', methods=['GET', 'POST'])
def creategroup():
    if request.method == 'POST':
        group_name = request.form.get('groupName')
        if group_name:
            new_group = Group(name=group_name)
            db.session.add(new_group)
            db.session.commit()
            flash('Group created successfully!', 'success')
            return redirect(url_for('creategroup'))

    groups = Group.query.all()
    return render_template('creategroup.html',groups=groups, logged_in=True, user_role=session.get('role'))

@app.route('/group/<int:group_id>', methods=['GET'])
def group_details(group_id):
    group = Group.query.get_or_404(group_id)
    members = GroupMember.query.filter_by(group_id=group_id).all()
    return render_template('group_dteails.html', group=group, members=members,logged_in=True, user_role=session.get('role'))

@app.route('/group/<int:group_id>/remove_member/<int:user_id>', methods=['POST'])
def remove_group_member(group_id, user_id):
    group_member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first_or_404()
    db.session.delete(group_member)
    db.session.commit()
    flash('Member removed successfully!', 'success')
    return redirect(url_for('group_details', group_id=group_id))

@app.route('/joingroup', methods=['GET', 'POST'])
def join_group():
    if 'logged_in' not in session or session['role'] != 'Learner':
        return redirect(url_for('login'))

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if group_name:
            group = Group.query.filter_by(name=group_name).first()
            if group:
                new_member = GroupMember(group_id=group.id, user_id=session['user_id'])
                db.session.add(new_member)
                db.session.commit()
                flash('Joined group successfully!', 'success')
            else:
                flash('Group not found.', 'danger')
        else:
            flash('Group name cannot be empty.', 'danger')
        return redirect(url_for('join_group'))

    # Fetch all groups to display in the template
    groups = Group.query.all()
    return render_template('joingroup.html',groups=groups, logged_in=True, user_role=session.get('role'))

@app.route('/leave_group/<string:group_name>', methods=['POST'])
def leave_group(group_name):
    if 'logged_in' not in session or session['role'] != 'Learner':
        return redirect(url_for('login'))

    group = Group.query.filter_by(name=group_name).first()
    if group:
        group_member = GroupMember.query.filter_by(group_id=group.id, user_id=session['user_id']).first()
        if group_member:
            db.session.delete(group_member)
            db.session.commit()
            flash(f'You have left the group {group_name}.', 'success')
        else:
            flash('You are not a member of this group.', 'danger')
    else:
        flash('Group not found.', 'danger')

    return redirect(url_for('join_group'))

@app.route('/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    if 'logged_in' not in session or session['role'] != 'Instructor':
        return redirect(url_for('login'))
    
    group = Group.query.get_or_404(group_id)
    
    # Delete all group members first
    GroupMember.query.filter_by(group_id=group.id).delete()
    
    # Delete the group
    db.session.delete(group)
    db.session.commit()
    
    flash('Group deleted successfully!', 'success')
    return redirect(url_for('creategroup'))


@app.route('/remove_member/<string:group_name>/<string:member_name>', methods=['POST'])
def remove_member(group_name, member_name):
    if 'logged_in' not in session or session['role'] != 'Instructor':
        return redirect(url_for('login'))

    group = Group.query.filter_by(name=group_name).first()
    member = User.query.filter_by(username=member_name).first()
    if group and member:
        group_member = GroupMember.query.filter_by(group_id=group.id, user_id=member.id).first()
        if group_member:
            db.session.delete(group_member)
            db.session.commit()
            flash(f'Member {member_name} removed from group {group_name}.', 'success')
        else:
            flash('Member not found in the group.', 'danger')
    else:
        flash('Group or Member not found.', 'danger')

    return redirect(url_for('creategroup'))

@app.route('/overview')
def overview():
    return render_template('overview.html')

@app.route('/contact')
def contact():
    return render_template('contact.html',logged_in=True, user_role=session.get('role'))

@app.route('/after_attack', methods=['GET'])
def after_attack():
    attack_type = request.args.get('attackType', 'default')
    video_urls = {
        'dos': url_for('static', filename='videos/DoS_Visualization_-_Made_with_Clipchamp.mp4'),
        'tcp': url_for('static', filename='videos/TCP_Visualization_-_Made_with_Clipchamp.mp4'),
        'arp': url_for('static', filename='videos/ARP_Visualization_-_Made_with_Clipchamp.mp4')
    }
    video_url = video_urls.get(attack_type, url_for('static', filename='videos/default.mp4'))
    return render_template('after_attack.html', attack_type=attack_type, video_url=video_url,logged_in=True, user_role=session.get('role'))

@app.route('/attack_action', methods=['POST'])
def attack_action():
    attack_type = request.form['attackType']
    if attack_type == 'dos':
        return dos_attack()
    elif attack_type == 'arp':
        return arp_poisoning()
    elif attack_type == 'tcp':
        return tcp_port_scan()
    
    else:
        flash('Invalid attack type selected', 'danger')
        return redirect(url_for('attack'))
    
@app.route('/attack_details/<int:simulation_id>')
def attack_details(simulation_id):
    simulation = Simulation.query.get_or_404(simulation_id)
    return render_template('attack_details.html', simulation=simulation,logged_in=True, user_role=session.get('role'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        role_id = int(request.form['role_id'])  # Convert the string to an integer
        instructor_id = None

        if role_id == Role.query.filter_by(role_name='Instructor').first().id:
            instructor_id = str(uuid4())

        new_user = User(
            username=request.form['username'],
            email=request.form['email'],
            password=hashed_password,
            role_id=role_id,
            instructor_id=instructor_id
        )

        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    
    roles = Role.query.all()
    return render_template('signup.html', roles=roles)

@app.route('/forgetpassword', methods=['GET', 'POST'])
def forgetpassword():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('An email with password reset instructions has been sent.', 'info')
        else:
            flash('No account found with that email address.', 'danger')
    return render_template('forgetpassword.html')

@app.route('/learner_dashboard', methods=['GET', 'POST'])
def learner_dashboard():
    if 'logged_in' not in session or session['role'] != 'Learner':
        return redirect(url_for('login'))

    if request.method == 'POST':
        instructor_id = request.form['instructor_id']
        instructor = User.query.filter_by(id=instructor_id, role_id=Role.query.filter_by(role_name='Instructor').first().id).first()
        if instructor:
            new_request = InstructorRequest(learner_id=session['user_id'], instructor_id=instructor_id)
            db.session.add(new_request)
            db.session.commit()
            flash('Request submitted successfully!', 'success')
        else:
            flash('Invalid Instructor ID.', 'danger')

    return render_template('learner_dashboard.html')

@app.route('/instructor_dashboard', methods=['GET'])
def instructor_dashboard():
    if 'logged_in' not in session or session['role'] != 'Instructor':
        return redirect(url_for('login'))

    instructor = User.query.filter_by(id=session['user_id']).first()
    pending_requests = InstructorRequest.query.filter_by(instructor_id=session['user_id'], status='pending').all()

    return render_template('instructor_dashboard.html', instructor_id=instructor.instructor_id, pending_requests=pending_requests)

@app.route('/approve_request/<int:request_id>', methods=['POST'])
def approve_request(request_id):
    if 'logged_in' not in session or session['role'] != 'Instructor':
        return redirect(url_for('login'))

    request = InstructorRequest.query.get_or_404(request_id)
    if request.instructor_id != session['user_id']:
        return "Unauthorized", 403

    request.status = 'approved'
    learner = User.query.get(request.learner_id)
    learner.instructor_id = request.instructor_id
    db.session.commit()

    flash('Learner request approved', 'success')
    return redirect(url_for('instructor_dashboard'))

@app.route('/deny_request/<int:request_id>', methods=['POST'])
def deny_request(request_id):
    if 'logged_in' not in session or session['role'] != 'Instructor':
        return redirect(url_for('login'))

    request = InstructorRequest.query.get_or_404(request_id)
    if request.instructor_id != session['user_id']:
        return "Unauthorized", 403

    request.status = 'denied'
    db.session.commit()

    flash('Learner request denied', 'success')
    return redirect(url_for('instructor_dashboard'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'logged_in' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form['action']
        if action == 'delete_user':
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully', 'success')
        elif action == 'add_user':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role_id = request.form['role_id']
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, email=email, password=hashed_password, role_id=role_id)
            db.session.add(new_user)
            db.session.commit()
            flash('New user added successfully', 'success')

    users = User.query.all()
    simulations = Simulation.query.all()
    feedbacks = Feedback.query.all()

    # For analytics
    tcp_count = Simulation.query.filter_by(attack_type='TCP Port Scan').count()
    arp_poisoning_count = Simulation.query.filter_by(attack_type='ARP Poisoning').count()
    dos_count = Simulation.query.filter_by(attack_type='DoS').count()

    roles = Role.query.all()
    return render_template('admin_dashboard.html', users=users, simulations=simulations, feedbacks=feedbacks, tcp_count=tcp_count, arp_poisoning_count=arp_poisoning_count, dos_count=dos_count, roles=roles)

@app.route('/dos_attack', methods=['POST'])
def dos_attack():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    target_ip = request.form['target_ip']
    packets = request.form.get('packets', 1000)  # Default to 1000 packets if not specified

    user = User.query.filter_by(username=session['username']).first()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    pcap_dir = 'pcap_files'
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_filename = f"{user.username}_{timestamp}.pcap"
    pcap_filepath = os.path.join(pcap_dir, pcap_filename)

    try:
        # Start tcpdump to capture packets
        tcpdump_command = f"sudo tcpdump -i any -w {pcap_filepath}"
        tcpdump_process = subprocess.Popen(tcpdump_command, shell=True, preexec_fn=os.setsid)
        print(f"Started tcpdump with PID {tcpdump_process.pid} to capture packets to {pcap_filepath}")

        # Run the DoS attack
        hping3_command = f"sudo hping3 -S --flood -c {packets} {target_ip}"
        hping3_result = subprocess.run(hping3_command, shell=True, capture_output=True, text=True)
        print(f"DoS attack command executed: {hping3_command}")

        # Stop tcpdump after the attack
        os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)
        print(f"Stopped tcpdump with PID {tcpdump_process.pid}")

        # Check if pcap file was created
        if not os.path.exists(pcap_filepath):
            raise FileNotFoundError(f"PCAP file {pcap_filepath} was not created.")
        if os.path.getsize(pcap_filepath) == 0:
            raise ValueError(f"PCAP file {pcap_filepath} is empty. No packets captured.")

    except Exception as e:
        print(f"Error during DoS attack and packet capture: {e}")
        return f"Error: {e}"

    # Create a new Simulation entry
    new_simulation = Simulation(user_id=user.id, attack_type='DoS', status='Completed')
    db.session.add(new_simulation)
    db.session.commit()

    # Log the attack
    log_attack(new_simulation.id, user.id, 'DoS attack using hping3', f"target_ip={target_ip}, packets={packets}")

    # Save the PCAP file information
    save_pcap(new_simulation.id, pcap_filepath)

    # Redirect to feedback form
    return redirect(url_for('feedback_form', simulation_id=new_simulation.id))

@app.route('/tcp_port_scan', methods=['POST'])
def tcp_port_scan():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    target_ip = request.form['target_ip']
    user = User.query.filter_by(username=session['username']).first()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    pcap_dir = 'pcap_files'
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_filename = f"{user.username}_{timestamp}.pcap"
    pcap_filepath = os.path.join(pcap_dir, pcap_filename)

    try:
        # Start tcpdump to capture packets
        tcpdump_command = f"sudo tcpdump -i eth0 -w {pcap_filepath}"  # Replace eth0 with the correct interface
        tcpdump_process = subprocess.Popen(tcpdump_command, shell=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Started tcpdump with PID {tcpdump_process.pid} to capture packets to {pcap_filepath}")

        # Run the TCP port scan using nmap
        nmap_command = f"sudo nmap -sS {target_ip}"
        nmap_result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
        print(f"TCP port scan command executed: {nmap_command}")
        print(f"nmap output: {nmap_result.stdout}")
        print(f"nmap errors: {nmap_result.stderr}")

        # Allow some time for tcpdump to capture all packets
        time.sleep(10)  # sleep for 10 seconds

        # Stop tcpdump after the scan
        os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)
        print(f"Stopped tcpdump with PID {tcpdump_process.pid}")

        # Check if pcap file was created and not empty
        if not os.path.exists(pcap_filepath):
            raise FileNotFoundError(f"PCAP file {pcap_filepath} was not created.")
        if os.path.getsize(pcap_filepath) == 0:
            raise ValueError(f"PCAP file {pcap_filepath} is empty. No packets captured.")

    except Exception as e:
        print(f"Error during TCP port scan and packet capture: {e}")
        return f"Error: {e}"

    # Create a new Simulation entry
    new_simulation = Simulation(user_id=user.id, attack_type='TCP Port Scan', status='Completed')
    db.session.add(new_simulation)
    db.session.commit()

    # Log the attack
    log_attack(new_simulation.id, user.id, 'TCP Port Scan using nmap', f"target_ip={target_ip}")

    # Save the PCAP file information
    save_pcap(new_simulation.id, pcap_filepath)

    # Redirect to feedback form
    return redirect(url_for('feedback_form', simulation_id=new_simulation.id))

@app.route('/arp_poisoning', methods=['POST'])
def arp_poisoning():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    target_ip = request.form['target_ip']
    gateway_ip = request.form['gateway_ip']
    user = User.query.filter_by(username=session['username']).first()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    pcap_dir = 'pcap_files'
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_filename = f"{user.username}_{timestamp}.pcap"
    pcap_filepath = os.path.join(pcap_dir, pcap_filename)

    try:
        # Start tcpdump to capture packets
        tcpdump_command = f"sudo tcpdump -i any -w {pcap_filepath}"
        tcpdump_process = subprocess.Popen(tcpdump_command, shell=True, preexec_fn=os.setsid)
        print(f"Started tcpdump with PID {tcpdump_process.pid} to capture packets to {pcap_filepath}")

        # Run the ARP Poisoning attack using arpspoof
        arpspoof_command = f"sudo arpspoof -i eth0 -t {target_ip} -r {gateway_ip}"
        arpspoof_process = subprocess.Popen(arpspoof_command, shell=True, preexec_fn=os.setsid)
        print(f"ARP Poisoning command executed: {arpspoof_command}")

        # Allow the ARP Poisoning attack to run for some time
        time.sleep(60)  # run the attack for 60 seconds

        # Stop arpspoof and tcpdump after the attack
        os.killpg(os.getpgid(arpspoof_process.pid), signal.SIGTERM)
        os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)
        print(f"Stopped arpspoof with PID {arpspoof_process.pid} and tcpdump with PID {tcpdump_process.pid}")

        # Check if pcap file was created
        if not os.path.exists(pcap_filepath):
            raise FileNotFoundError(f"PCAP file {pcap_filepath} was not created.")
        if os.path.getsize(pcap_filepath) == 0:
            raise ValueError(f"PCAP file {pcap_filepath} is empty. No packets captured.")

    except Exception as e:
        print(f"Error during ARP Poisoning attack and packet capture: {e}")
        return f"Error: {e}"

    # Create a new Simulation entry
    new_simulation = Simulation(user_id=user.id, attack_type='ARP Poisoning', status='Completed')
    db.session.add(new_simulation)
    db.session.commit()

    # Log the attack
    log_attack(new_simulation.id, user.id, 'ARP Poisoning using arpspoof', f"target_ip={target_ip}, gateway_ip={gateway_ip}")

    # Save the PCAP file information
    save_pcap(new_simulation.id, pcap_filepath)

    # Redirect to feedback form
    return redirect(url_for('feedback_form', simulation_id=new_simulation.id))
#
@app.route('/download_pcap/<int:pcap_id>')
def download_pcap(pcap_id):
    pcap = PCAP.query.get_or_404(pcap_id)
    if pcap.simulation.user_id != session['user_id'] and session['role'] != 'admin':
        return "Unauthorized", 403
    directory = os.path.dirname(pcap.file_path)
    filename = os.path.basename(pcap.file_path)
    return send_from_directory(directory, filename)
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('feedback.html',logged_in=True, user_role=session.get('role'))

@app.route('/feedback_form/<int:simulation_id>', methods=['GET', 'POST'])
def feedback_form(simulation_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        rating = request.form['rating']
        content = request.form.get('content', '')

        new_feedback = Feedback(
            user_id=session['user_id'],
            simulation_id=simulation_id,
            rating=rating,
            content=content,
            submitted_at=datetime.utcnow()
        )
        db.session.add(new_feedback)
        db.session.commit()
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('index'))

    return render_template('feedback_form.html', simulation_id=simulation_id)

def log_attack(simulation_id, user_id, description, parameters):
    """Log an attack in the Attack table."""
    try:
        new_attack = Attack(simulation_id=simulation_id, user_id=user_id, description=description, parameters=parameters, timestamp=datetime.utcnow())
        db.session.add(new_attack)
        db.session.commit()
        print(f"New attack logged: Simulation ID = {new_attack.simulation_id}, User ID = {new_attack.user_id}, Description = {new_attack.description}, Parameters = {new_attack.parameters}")
    except Exception as e:
        print(f"Error logging attack: {e}")

def save_pcap(simulation_id, file_path):
    """Save the PCAP file information."""
    try:
        new_pcap = PCAP(simulation_id=simulation_id, file_path=file_path)
        db.session.add(new_pcap)
        db.session.commit()
        print(f"New PCAP file saved: Simulation ID = {new_pcap.simulation_id}, File Path = {new_pcap.file_path}")
    except Exception as e:
        print(f"Error saving PCAP file: {e}")

# def init_db():
#     db.create_all()
#     if not Role.query.first():
#         roles = ['Learner', 'Researcher', 'Instructor', 'admin']
#         for role_name in roles:
#             role = Role(role_name=role_name)
#             db.session.add(role)
#         db.session.commit()
#     init_admin()

def init_db():
    with app.app_context():
        db.create_all()
        if not Role.query.first():
            roles = ['Learner', 'Researcher', 'Instructor', 'Admin']
            for role_name in roles:
                role = Role(role_name=role_name)
                db.session.add(role)
            db.session.commit()
        init_admin()

def init_admin():
    admin_role = Role.query.filter_by(role_name='admin').first()
    if not admin_role:
        admin_role = Role(role_name='admin')
        db.session.add(admin_role)
        db.session.commit()
        print("Admin role created")

    admin_user = User.query.filter_by(email='admin@example.com').first()
    if not admin_user:
        hashed_password = generate_password_hash('admin_password', method='pbkdf2:sha256')
        admin_user = User(username='admin@example.com', email='admin@example.com', password=hashed_password, role_id=admin_role.id)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created")
    else:
        print("Admin user already exists")


if __name__ == '__main__':
    # init_db()
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
