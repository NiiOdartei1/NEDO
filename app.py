from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from functools import wraps
import secrets
from decimal import Decimal
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import func , select
import os, logging, base64, sys, requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ngo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SECRET_KEY'] = 'supersecretkey'
app.permanent_session_lifetime = timedelta(minutes=1)

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='lampteyjoseph860@gmail.com',
    MAIL_PASSWORD='fthu ehdz pczl abcw'
)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins='*')

def send_email(to, subject, body, unsubscribe_token=None):
    if not unsubscribe_token:
        raise ValueError("unsubscribe_token must be provided for unsubscribe link.")
    msg = Message(subject, recipients=[to], sender='lampteyjoseph860@gmail.com')
    unsubscribe_link = url_for('unsubscribe', token=unsubscribe_token, _external=True)
    personalized_body = body.replace("{{unsubscribe_link}}", unsubscribe_link)
    msg.body = "This email requires an HTML viewer."
    msg.html = personalized_body
    mail.send(msg)

db = SQLAlchemy(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi'}
ALLOWED_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS.union(ALLOWED_VIDEO_EXTENSIONS)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Fixed super admin credentials
SUPER_ADMIN_USERNAME = 'mainadmin'
SUPER_ADMIN_PASSWORD = generate_password_hash('password123')

logging.basicConfig(level=logging.DEBUG)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request_tasks():
    session.permanent = True
    db.create_all()

#@app.before_request
#def ensure_seed_fund():
#   existing = Funding.query.first()
#    if not existing:
#        seed = Funding(
#            total_amount=Decimal("30000.00"),
#            description="Initial fixed seed capital"
#        )
#        db.session.add(seed)
#        db.session.commit()


@app.route('/admin/logout-on-close', methods=['POST'])
def logout_on_close():
    session.pop('admin', None)
    return '', 204  # No content response

# ------------ MODELS --------------------
class NewsArticle(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(255), nullable=False)
    content     = db.Column(db.Text, nullable=False)
    media_urls  = db.Column(db.Text, nullable=True)    # NEW
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)
    archived_date = db.Column(db.DateTime)

class FeaturedProject(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    title         = db.Column(db.String(255), nullable=False)
    description   = db.Column(db.Text, nullable=False)
    media_urls    = db.Column(db.Text, nullable=True)  # NEW
    date_created  = db.Column(db.DateTime, default=datetime.utcnow)
    link          = db.Column(db.String(255), nullable=True)
    is_archived = db.Column(db.Boolean, default=False)
    archived_date = db.Column(db.DateTime)

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class NewsletterSubscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    subscribed_on = db.Column(db.DateTime, default=datetime.utcnow)
    unsubscribe_token = db.Column(db.String(64), unique=True, nullable=True)

    def generate_unsubscribe_token(self):
        self.unsubscribe_token = secrets.token_urlsafe(32)

class NewsletterSent(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    subject     = db.Column(db.String(255), nullable=False)
    message     = db.Column(db.Text, nullable=False)
    sent_on     = db.Column(db.DateTime, default=datetime.utcnow)

class Funding(db.Model):
    __tablename__ = "funding"

    id            = db.Column(db.Integer, primary_key=True)
    total_amount  = db.Column(db.Numeric(precision=12, scale=2), nullable=False, default=Decimal("30000.00"))
    description   = db.Column(db.String(255), nullable=True)   # e.g. "Initial seed fund"
    date_created  = db.Column(db.DateTime, default=datetime.utcnow)
    is_active     = db.Column(db.Boolean, default=True)         # If you ever “close” or “archive” this fund

    # One-to-many relationship to individual contributions (optional)
    contributions = db.relationship(
        "Contribution",
        backref="funding",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )

    @hybrid_property
    def amount_raised(self):
        total_contributions = sum([c.amount for c in self.contributions])
        return self.total_amount + total_contributions

    @amount_raised.expression
    def amount_raised(cls):
        return cls.total_amount + (
            select([func.coalesce(func.sum(Contribution.amount), 0)])
            .where(Contribution.funding_id == cls.id)
            .label("total_contributions")
        )


class Contribution(db.Model):
    __tablename__ = "contributions"

    id            = db.Column(db.Integer, primary_key=True)
    funding_id    = db.Column(db.Integer, db.ForeignKey("funding.id"), nullable=False)
    investor_name = db.Column(db.String(255), nullable=False)
    amount        = db.Column(db.Numeric(precision=12, scale=2), nullable=False)
    date_added    = db.Column(db.DateTime, default=datetime.utcnow)
    note          = db.Column(db.String(255), nullable=True)   # e.g. “Angel investor A”

    # You could also track “use” of funds by negative amounts, if desired

# -------------------- HELPERS --------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def is_logged_in():
    return 'admin' in session

def is_super_admin():
    return session.get('admin') == SUPER_ADMIN_USERNAME

# -------------------- AUTH ROUTES --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check fixed super admin
        if username == SUPER_ADMIN_USERNAME and check_password_hash(SUPER_ADMIN_PASSWORD, password):
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))

        # Check database admin
        admin = AdminUser.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))

        flash('Invalid credentials', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/logout', methods=['GET', 'POST'])
def admin_logout():
    session.pop('admin', None)
    if request.method == 'POST':
        return '', 204  # For sendBeacon
    flash('Logged out successfully', 'info')
    return redirect(url_for('admin_login'))

# -------------------- SUPER ADMIN: CREATE ADMINS --------------------
@app.route('/admin/create', methods=['GET', 'POST'])
def create_admin():
    if not is_logged_in() or not is_super_admin():
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if AdminUser.query.filter_by(username=username).first():
            flash('Username already exists', 'warning')
        else:
            new_admin = AdminUser(username=username, password=generate_password_hash(password))
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('admin/create_admin.html')

# -------------------- PROTECTED ADMIN ROUTES --------------------
@app.route('/admin')
def admin_dashboard():
    if not is_logged_in():
        return redirect(url_for('admin_login'))

    total_news = NewsArticle.query.count()
    active_projects = FeaturedProject.query.count()
    admin_count = AdminUser.query.count() + 1  # Including super admin
    newsletter_count = NewsletterSubscriber.query.count()

    recent = []
    for art in NewsArticle.query.order_by(NewsArticle.date_posted.desc()).limit(5):
        recent.append({'date': art.date_posted.strftime('%Y-%m-%d'), 'action': f'News: "{art.title}"', 'user': 'Admin', 'status': 'New'})
    for proj in FeaturedProject.query.order_by(FeaturedProject.date_created.desc()).limit(5):
        recent.append({'date': proj.date_created.strftime('%Y-%m-%d'), 'action': f'Project: "{proj.title}"', 'user': 'Admin', 'status': 'Created'})

    recent_activity = sorted(recent, key=lambda x: x['date'], reverse=True)[:5]

    return render_template('admin/admin_dashboard.html',
                           total_news=total_news,
                           active_projects=active_projects,
                           admin_count=admin_count,
                           newsletter_count=newsletter_count,
                           recent_activity=recent_activity)

@app.route('/admin/users')
@login_required
def admin_users():
    admins = AdminUser.query.all()  # Or however you're retrieving admin users
    return render_template('admin/admin_users.html', admins=admins)

@app.route("/funding")
def view_funding():
    fund = Funding.query.first()
    contributions = fund.contributions.order_by(Contribution.date_added.desc()).all()
    return render_template("admin/funding.html", fund=fund, contributions=contributions)


@app.route("/admin/funding/add_contribution", methods=["GET", "POST"])
def add_contribution():
    """
    A simple form where an admin can log a new investor contribution.
    """
    fund = Funding.query.filter_by(is_active=True).first()
    if fund is None:
        flash("No active funding round found.", "danger")
        return redirect(url_for("view_funding"))

    if request.method == "POST":
        investor = request.form["investor_name"].strip()
        amount_str = request.form["amount"].strip()
        note = request.form.get("note", "").strip()

        try:
            amount = Decimal(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
        except Exception as e:
            flash("Enter a valid positive amount.", "warning")
            return redirect(url_for("add_contribution"))

        # Create a Contribution row
        contribution = Contribution(
            funding_id=fund.id,
            investor_name=investor,
            amount=amount,
            note=note or None
        )
        # Update the Funding.total_amount
        fund.total_amount = fund.total_amount + amount

        db.session.add(contribution)
        db.session.commit()
        flash(f"Recorded contribution of ${amount:.2f} from {investor}", "success")
        return redirect(url_for("view_funding"))

    return render_template("admin/add_contribution.html", fund=fund)

# -------------------- ADDITIONAL ROUTES --------------------
@app.route('/admin/create-news', methods=['GET', 'POST'])
@login_required
def create_news():
    if request.method == 'POST':
        title  = request.form['title']
        content= request.form['content']

        # handle multiple files
        uploaded = request.files.getlist('media[]')
        saved    = []
        for f in uploaded:
            if f and allowed_file(f.filename):
                fn = secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
                saved.append(fn)

        # comma‑separate
        media_field = ','.join(saved) if saved else None

        # 1️⃣ Create and commit
        article = NewsArticle(
            title      = title,
            content    = content,
            media_urls = media_field
        )
        db.session.add(article)
        db.session.commit()

        flash('News created and saved to DB!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/create_news.html')

@app.route('/news/<int:id>')
def news_detail(id):
    article = NewsArticle.query.get_or_404(id)
    return render_template('news_detail.html', article=article)

@app.route('/admin/news/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_news(id):
    article = NewsArticle.query.get_or_404(id)
    if request.method == 'POST':
        article.title = request.form['title']
        article.content = request.form['content']
        
        # If a new image is uploaded, update it
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                article.image_url = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        db.session.commit()
        flash('News updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_news.html', article=article)

@app.route('/admin/news/delete/<int:id>', methods=['POST'])
@login_required
def delete_news(id):
    article = NewsArticle.query.get_or_404(id)
    db.session.delete(article)
    db.session.commit()
    flash('News deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/news')
def news_list():
    news_items = NewsArticle.query.all()
    return render_template('admin/news_list.html', news_items=news_items)

#-----------------------PROJ ------------------
@app.route('/admin/create-project', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        title       = request.form['title']
        description = request.form['description']
        location    = request.form['location']
        status      = request.form['status']

        uploaded = request.files.getlist('media[]')
        saved    = []
        for f in uploaded:
            if f and allowed_file(f.filename):
                fn = secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
                saved.append(fn)

        media_field = ','.join(saved) if saved else None

        project = FeaturedProject(
            title       = title,
            description = description,
            media_urls  = media_field
        )
        db.session.add(project)
        db.session.commit()

        flash('Project created and saved to DB!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/create_project.html')

@app.route('/admin/projects')
def project_overview():
    if not is_logged_in():
        return redirect(url_for('admin_login'))
    
    all_projects = FeaturedProject.query.all()
    return render_template('admin/project.html', projects=all_projects)

@app.route('/admin/projects/active')
def active_projects():
    if not is_logged_in():
        return redirect(url_for('admin_login'))

    # Assuming you have a 'status' column on FeaturedProject
    active_list = FeaturedProject.query.filter_by(status='Active').all()
    return render_template('admin/active_projects.html',
                           projects=active_list)

# Manage Projects – list with edit/delete buttons
@app.route('/admin/projects/manage')
def manage_projects():
    if not is_logged_in():
        return redirect(url_for('admin_login'))
    projects = FeaturedProject.query.all()
    return render_template('admin/manage_projects.html', projects=projects)

@app.route('/admin/projects/edit/<int:id>', methods=['POST'])
@login_required
def edit_project(id):
    project = FeaturedProject.query.get_or_404(id)
    project.title = request.form['title']
    project.description = request.form['description']
    project.link = request.form.get('link', '')

    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            project.image_url = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    db.session.commit()
    flash('Project updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/news/delete', methods=['POST'])
@login_required
def delete_news_api():
    id = request.form.get('id')
    NewsArticle.query.filter_by(id=id).delete()
    db.session.commit()
    return jsonify({'message': 'News deleted'}), 200

@app.route('/admin/projects/delete', methods=['POST'])
@login_required
def delete_project_api():
    id = request.form.get('id')
    FeaturedProject.query.filter_by(id=id).delete()
    db.session.commit()
    return jsonify({'message': 'Project deleted'}), 200

@app.route('/news')
def news():
    news_articles = NewsArticle.query.order_by(NewsArticle.date_posted.desc()).all()
    featured_projects = FeaturedProject.query.all()
    return render_template('news.html', news_articles=news_articles, featured_projects=featured_projects)

@app.route('/')
def index():
    total_raised = db.session.query(func.sum(Contribution.amount)).scalar() or Decimal("0.00")

    total_contributors = db.session.query(func.count(Contribution.id)).scalar() or 0

    # ✅ Limit to 10 most recent contributions
    recent_contributions = (
        Contribution.query
        .order_by(Contribution.date_added.desc())
        .limit(10)
        .all()
    )

    goal_amount = Decimal("1000000.00")
    progress_percentage = min((total_raised / goal_amount) * 100, Decimal("100.00"))

    return render_template(
        "index.html",
        total_raised=total_raised,
        goal_amount=goal_amount,
        progress_percentage=progress_percentage,
        total_contributors=total_contributors,
        recent_contributions=recent_contributions
    )

#----------- ABOUT US ------------------
@app.route('/mission-vision')
def mission_vision():
    return render_template('mission_vision.html')

@app.route("/about")
def about():
    return render_template("about.html")

@app.route('/testimonials')
def testimonials():
    print("Rendering testimonials.html")
    reviews = [
        {"name": "John Doe", "text": "Amazing platform!"},
        {"name": "Jane Smith", "text": "This service changed my life."},
        {"name": "Carlos M.", "text": "Highly recommended!"}
    ]
    return render_template('testimonials.html', reviews=reviews)


#----------- ARTICLES ------------------
@app.route('/stories')
def stories():
    app.logger.info("Rendering stories.html")
    print("Rendering stories.html")
    return render_template('stories.html')

@app.route('/programs')
def programs():
    app.logger.info("Rendering programs.html")
    print("Rendering programs.html")
    return render_template('programs.html')

@app.route('/articles/impact')
def impact_article():
    print("Rendering impact.html")
    return render_template('impact.html')

@app.route("/articles/innovation")
def innovation():
    return render_template("innovation.html")

#-------------------------------------------
@app.route('/women-empowerment')
def women_empowerment():
    return render_template('women_empowerment.html')

@app.route('/education')
def education():
    return render_template('education.html')  # Ensure education.html exists

@app.route('/healthcare')
def healthcare():
    return render_template('healthcare.html')

@app.route('/agriculture')
def agriculture():
    return render_template('agriculture.html')

@app.route('/mineral-resource-management')
def mineral_resource_management():
    return render_template('minerals.html')

@app.route('/industrial-development-and-innovation')
def industrial_development_and_innovation():
    return render_template('industrial_development_and_innovation.html')

@app.route('/ecommerce-and-digital-transformation')
def ecommerce_and_digital_transformation():
    return render_template('ecommerce_and_digital_transformation.html')

@app.route('/financial-inclusion')
def financial_inclusion():
    return render_template('financial_inclusion.html')

@app.route('/infrastructure-development-and-economic-resilience')
def infrastructure():
    return render_template('infrastructure.html')

@app.route('/global-collaboration-and-partnerships')
def global_collaboration_and_partnerships():
    return render_template('global_collaboration.html')

@app.route('/climate-change-adaptation-and-mitigation')
def climate_change_adaptation_and_mitigation():
    return render_template('climate_change.html') 

@app.route('/water-sustainability-and-management')
def water_sustainability_and_management():
    return render_template('water_sustainability.html')

@app.route('/green-energy')
def green_energy():
    return render_template('green_energy.html')

@app.route('/circular-economy')
def circular_economy():
    return render_template('circular_economy.html')

#----------- PROJECTS ------------------
@app.route('/projects/<name>')
def featured_project(name):
    # You can render a template dynamically based on `name`
    return render_template('projects/featured_project.html', project_name=name)

#----------- DONATE ------------------
@app.route('/donate')
def donate():
    print("Rendering donate.html")
    return render_template('donate.html')

#-----------CONTACT_US------------------
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        message = request.form["message"]

        # Here you can add code to save the message to a database or send an email

        flash("Thank you for contacting us! We will get back to you soon.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html")

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/youth-empowerment')
def youth_empowerment():
    return render_template('youth_empowerment.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

#----------- DONATE ------------------
import base64

def send_sms(to_number, message):
    client_id = 'your_hubtel_client_id'
    client_secret = 'your_hubtel_client_secret'
    sender_id = 'NEDO-Global'  # must be approved by Hubtel

    url = "https://smsc.hubtel.com"

    headers = {
        "Authorization": "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode(),
        "Content-Type": "application/json"
    }

    data = {
        "From": sender_id,
        "To": to_number,
        "Content": message
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        print("SMS sent successfully")
    else:
        print("Failed to send SMS", response.text)

#  ----------- NEWSLETTER SUBSCRIPTION ------------------
@app.route('/admin/newsletter-dashboard')
def newsletter_dashboard():
    # Fetch all sent newsletters
    sent_list = NewsletterSent.query.order_by(NewsletterSent.sent_on.desc()).all()
    # Fetch current subscribers and total count
    subs = NewsletterSubscriber.query.order_by(NewsletterSubscriber.subscribed_on.desc()).all()
    subscriber_count = len(subs)

    return render_template(
        'admin/newsletter_dashboard.html',
        sent_list=sent_list,
        subscribers=subs,
        subscriber_count=subscriber_count
    )

#  ----------- NOTIFICATIONS ------------------
@app.route('/notifications')
def notifications():
    newsletters = NewsletterSent.query.order_by(NewsletterSent.sent_on.desc()).all()
    return render_template('notifications.html', newsletters=newsletters)

@app.route('/notification/<int:notification_id>')
def notification_detail(notification_id):
    n = NewsletterSent.query.get_or_404(notification_id)
    return render_template('partials/notification_detail.html', notification=n)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

def emit_new_notification(subject, message, date):
    socketio.emit('new_notification', {
        'subject': subject,
        'message': message,
        'date': date
    })

#  ----------- ADMIN NEWSLETTER MANAGEMENT ------------------
@app.route("/admin/newsletters")
def admin_newsletters():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    newsletters = NewsletterSent.query.order_by(NewsletterSent.sent_at.desc()).all()
    subscriber_count = NewsletterSubscriber.query.count()

    return render_template("admin/newsletters.html",
                           newsletters=newsletters,
                           subscriber_count=subscriber_count)

@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email")
    if email:
        existing = NewsletterSubscriber.query.filter_by(email=email).first()
        if existing:
            flash("You're already subscribed!", "info")
        else:
            new_sub = NewsletterSubscriber(email=email)
            new_sub.generate_unsubscribe_token()
            db.session.add(new_sub)
            db.session.commit()
            flash("You have successfully subscribed!", "success")
    else:
        flash("Please enter a valid email.", "danger")
    return redirect(url_for("index"))

@app.route("/admin/newsletter/send", methods=["GET", "POST"])
def send_newsletter():
    if request.method == "POST":
        subject = request.form.get("subject")
        raw_message = request.form.get("message")
        subscribers = NewsletterSubscriber.query.all()

        # Save newsletter record
        newsletter_record = NewsletterSent(subject=subject, message=raw_message)
        db.session.add(newsletter_record)
        db.session.commit()

        for sub in subscribers:
            personalized_message = raw_message.replace(
                "{{unsubscribe_link}}",
                f"{request.url_root.rstrip('/')}/unsubscribe/{sub.unsubscribe_token}"
            )
            send_email(sub.email, subject, personalized_message, unsubscribe_token=sub.unsubscribe_token)

        flash("Newsletter sent successfully!", "success")
        return redirect(url_for('admin_newsletters'))

    return render_template("admin/send_newsletter.html")

@app.route("/unsubscribe/<token>")
def unsubscribe(token):
    subscriber = NewsletterSubscriber.query.filter_by(unsubscribe_token=token).first()
    if not subscriber:
        flash("Invalid or expired unsubscribe link.", "danger")
        return redirect(url_for("index"))

    db.session.delete(subscriber)
    db.session.commit()
    flash("You have been unsubscribed successfully.", "success")
    return redirect(url_for("index"))

@app.route("/admin/newsletter/backfill_tokens")
def backfill_unsubscribe_tokens():
    if 'admin' not in session:
        return redirect(url_for("admin_login"))

    subscribers = NewsletterSubscriber.query.filter_by(unsubscribe_token=None).all()
    count = 0
    for sub in subscribers:
        sub.generate_unsubscribe_token()
        count += 1
    db.session.commit()
    return f"Generated unsubscribe tokens for {count} subscribers."

#_____________ MOBILE ROUTES ______________
@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/serviceworker.js')
def service_worker():
    return send_from_directory('static', 'serviceworker.js')

#----------- Error handling for 404 ------------------
@app.errorhandler(404)
def page_not_found(e):
    print("404 error triggered")
    return render_template('404.html'), 404

import webbrowser
import threading
import signal

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

def graceful_exit(signum, frame):
    print("\nServer stopped (SIGTERM or Stop button)")
    sys.exit(0)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Handle Ctrl+C (SIGINT) and Stop Button (SIGTERM)
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    threading.Timer(1.5, open_browser).start()

    print("Starting Flask-SocketIO app…")
    try:
        socketio.run(app, host='127.0.0.1', port=5000, debug=False, use_reloader=False)
    except Exception as e:
        print(f"SocketIO server crashed with error: {e}", file=sys.stderr)
        sys.exit(1)
