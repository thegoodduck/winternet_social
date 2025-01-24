################################
#          IMPORTS             #
################################
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, Response, flash
import csv
from werkzeug.utils import secure_filename
import dropbox
import datetime
import hashlib
import requests
import ast
import math
import os
import string
from collections import OrderedDict
from markupsafe import Markup, escape
import time
import threading
import json

# TODO Add rendering of the media variably so until not scrolled its not rendered for bandwidht reduction 😂

last_post_time = {}


if os.path.exists('groups.csv'):
    with open('groups.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        groups = list(reader)

# Load group posts from CSV
if os.path.exists('group_posts.csv'):
    with open('group_posts.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        group_posts = list(reader)

#######################################
#               CONF                  #
#######################################
app = Flask(__name__)
app.debug = True
app.secret_key = 'super secret key'

# Set up Dropbox access token
DROPBOX_ACCESS_TOKEN = ''
key = ''
secret = ''
refresh = ''

# Initialize Dropbox client
dbx = dropbox.Dropbox(
    app_key=key,
    app_secret=secret,
    oauth2_refresh_token=refresh
)
###########################################
#               FILE RELATED               #
###########################################
# Read existing posts from CSV
try:
    with open('posts.csv', mode='r', encoding='utf-8', newline='') as file:
        reader = csv.reader(file)
        posts = []
        for row in reader:
            # Ensure the comments section is parsed as a list
            row[2] = eval(row[2])
            posts.append(row)
except FileNotFoundError:
    posts = []

try:
    with open('restricted.csv', mode='r', encoding='utf-8') as restricted_file:
        restricted_users = set(row.strip() for row in restricted_file)
except FileNotFoundError:
    restricted_users = set()

# Read sudo users from sudo.csv
try:
    with open('sudo.csv', mode='r', encoding='utf-8') as sudo_file:
        sudo_users = set(row.strip() for row in sudo_file)
except FileNotFoundError:
    sudo_users = set()
locked_users = set()

# Load locked users from locked.csv
try:
    with open('locked.csv', mode='r', encoding='utf-8') as locked_file:
        locked_users = set(locked_file.read().splitlines())
except FileNotFoundError:
    pass  # Handle the case where the file doesn't exist

def read_users():
    try:
        with open('users.csv', mode='r', encoding='utf-8') as users_file:
            reader = csv.reader(users_file)
            users = OrderedDict((row[0], row[1]) for row in reader)
    except FileNotFoundError:
        users = OrderedDict()
    return users

# Read posts from posts.csv
def read_posts():
    try:
        with open('posts.csv', mode='r', encoding='utf-8', newline='') as posts_file:
            reader = csv.reader(posts_file)
            posts = [row for row in reader]
    except FileNotFoundError:
        posts = []
    return posts
################################
#           DEFINITIONS        #
################################

class DataClass:
    @staticmethod
    def hash_password(password):
        """Hashes a password using SHA-256"""
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        return sha256.hexdigest()
    @staticmethod
    def hash_password2(password):
        # beta branch implement in future in Winternet 2.0... Lol
        """Hashes a password using SHA-512"""
        sha256 = hashlib.sha512()
        sha256.update(password.encode('utf-8'))
        return sha256.hexdigest()

    @staticmethod
    def log_action(action):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip_address = request.remote_addr
        user_agent = request.user_agent.string
        user = session.get('username', 'Unknown')

        log_entry = f"{timestamp} - IP: {ip_address} - User: {user} - Action: {action} - User Agent: {user_agent} \n"

        with open('logs.txt', 'a') as log_file:
            log_file.write(log_entry)

    @staticmethod
    def search_posts(query):
        results = []
        with open('posts.csv', 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                post_text = row[0].lower()
                user = row[1].lower()  # Assuming post text is in the first column
                post_words = post_text.split()  # Splitting post text into individual words
                query_words = query.lower().split()  # Splitting query into individual words
                if any(word in post_words for word in query_words) or any(word in user for word in query_words):
                    results.append({
                        'text': row[0],
                        'user': row[1],
                        'comments': eval(row[2]),  # Assuming comments are stored as a list
                        'image_url': row[3]
                    })
        return results
################################################################################
#                             APP ROUTES                                       #
################################################################################
@app.route('/logs', methods=['GET', 'POST'])
def logread():
    if 'username' not in session or session['username'] not in sudo_users:
        return redirect(url_for('login'))
    query = None
    results = []

    # Read the logs from logs.txt
    with open('logs.txt', mode='r', encoding='utf-8') as file:
        logs = file.readlines()[::-1]

    if request.method == 'POST':
        query = request.form['search']
        # Filter the logs based on the query
        results = [log for log in logs if query.lower() in log.lower()]
    else:
        # Show all logs if no search query is entered
        results = logs

    return render_template('logs.html', logs=results, query=query)
@app.route('/credits')
def credits():
    return render_template('credits.html')
@app.route('/search')
def search_page():
    query = request.args.get('q', '')
    post_results = DataClass.search_posts(query)  # Search posts.csv for matching posts
    return render_template('search.html', query=query, post_results=post_results)
def generate_sitemap():
    output = []
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            # Create the URL for each rule
            url = url_for(rule.endpoint, _external=True)
            # Append the sitemap entry
            output.append(f"""
                <url>
                    <loc>{url}</loc>
                </url>
            """)

    sitemap_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        {''.join(output)}
    </urlset>"""

    return sitemap_xml
CSV_FILE = 'servers.csv'

# Create the CSV file if it doesn't exist
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        # Write the header row
        writer.writerow(['Server Address', 'Description'])

# Route for the pastebin
@app.route('/pastebin', methods=['GET', 'POST'])
def pastebin():
    if request.method == 'POST':
        if 'username' not in session:
            return redirect(url_for('login'))
        # Get the server address and description from the form
        server_address = request.form.get('server_address')
        description = request.form.get('description')

        # Append the server address and description to the CSV file
        with open(CSV_FILE, mode='a', encoding='utf-8', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([server_address, description])
        # Redirect back to the pastebin page
        return redirect(url_for('pastebin'))

    # Read the server addresses and descriptions from the CSV file
    pastes = []
    with open(CSV_FILE, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            pastes.append(row)
    pastes.reverse()

    # Count the number of times each link has been clicked
    link_clicks = {}
    for paste in pastes:
        link = paste[0]
        link_clicks[link] = link_clicks.get(link, 0) + 1

    # Sort pastes by number of clicks in descending order
    pastes.sort(key=lambda x: link_clicks.get(x[0], 0), reverse=True)

    # Render the pastebin.html template and pass the pastes list
    return render_template('pastebin.html', pastes=pastes)
@app.route('/view_paste/<int:index>')
def view_paste(index):
    # Read the specific pastebin entry from the CSV file using the index
    pastes = []
    with open(CSV_FILE, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            pastes.append(row)

    # Ensure the index is within the range of pastes
    if index < 0 or index >= len(pastes):
        return "Invalid index", 404

    # Retrieve the pastebin entry based on the provided index
    paste_entry = pastes[index]

    # Render the 'view_paste.html' template and pass the paste_entry
    return render_template('view_paste.html', server_address=paste_entry[0], description=paste_entry[1])
# Flask route to serve the sitemap
@app.errorhandler(500)
def ouch():
    return render_template('error.html')
@app.route('/sitemap.xml')
def sitemap():
    sitemap_xml = generate_sitemap()
    response = Response(sitemap_xml, mimetype='application/xml')
    return response



PROFILE_FILE = 'profile.csv'

# Function to read profile data from CSV
def read_profile(username):
    with open(PROFILE_FILE, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username:
                return {
                    'username': row[0],
                    'email': row[1],
                    'full_name': row[2],
                    'bio': row[3]
                }
    return None

# Function to write profile data to CSV
def write_profile(profile):
    profiles = []
    with open(PROFILE_FILE, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        profiles = list(reader)

    with open(PROFILE_FILE, mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        found = False
        for row in profiles:
            if row[0] == profile['username']:
                writer.writerow([profile['username'], profile['email'], profile['full_name'], profile['bio']])
                found = True
            else:
                writer.writerow(row)

        # If profile not found, add a new entry
        if not found:
            writer.writerow([profile['username'], profile['email'], profile['full_name'], profile['bio']])

# Route to view a user's profile
@app.route('/profile/<username>')
def view_profile(username):
    profile = read_profile(username)
    if profile:
        return render_template('profile.html', profile=profile)
    else:
        return render_template('error.html',error_message='Pas de profil.')

# Route to edit a user's profile
@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    profile = read_profile(username)

    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        bio = request.form.get('bio')

        profile = {
            'username': username,
            'email': email,
            'full_name': full_name,
            'bio': bio
        }

        write_profile(profile)
        return redirect(url_for('view_profile', username=username))

    return render_template('edit_profile.html', profile=profile)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'),404

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect('/login')

    sender = session['username']
    receiver = request.form.get('receiver')
    message_text = request.form.get('message_text')

    message = [sender, receiver, message_text]

    with open('messages.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(message)
    DataClass.log_action(f"Sent message to {receiver}")
    return redirect('/messages')

@app.route('/messages')
def messages():
    if 'username' not in session:
        return redirect('/login')

    messages = []
    with open('messages.csv', mode='r', encoding='utf-8', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if session['username'].lower() in (row[0].lower(), row[1].lower()):
                messages.append(row)

    return render_template('messages.html', messages=messages)

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error."}), 500

@app.route('/modify_post/<int:post_index>', methods=['POST'])
def modify_post(post_index):
    if 'username' not in session or session['username'] not in sudo_users:
        return redirect(url_for('login'))

    modified_text = request.form.get('modified_text')
    modified_username = request.form.get('modified_username')
    modified_image = request.form.get('modified_image')

    posts = read_posts()
    if 0 <= post_index < len(posts):
        # Update post details
        posts[post_index][0] = modified_text
        posts[post_index][1] = modified_username
        posts[post_index][3] = modified_image

        # Write updated posts to posts.csv
        with open('posts.csv', mode='a', encoding='utf-8', newline='') as posts_file:
            writer = csv.writer(posts_file)
            writer.writerows(posts)

        DataClass.log_action(f"Modified post at index {post_index}")

    return redirect(url_for('dashboard'))

# Route to handle lock/unlock action for a specific user
@app.route('/lock/<username>', methods=['POST','GET'])
def toggle_lock(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return render_template('error.html', error_message="Vous n'êtes pas administrateurs. (Tu n'as rien à foutre ici!!!)")

    action = request.form.get('action')
    if action == 'lock':
        locked_users.add(username)
        DataClass.log_action(f"Locked user: {username}")
    elif action == 'unlock':
        if username in locked_users:
            locked_users.remove(username)
            DataClass.log_action(f"Unlocked user: {username}")

    # Save locked users to locked.csv
    with open('locked.csv', 'w') as locked_file:
        for locked_user in locked_users:
            locked_file.write(locked_user + '\n')

    return redirect(url_for('dashboard'))

# Route to display the dashboard
@app.route('/dash')
def dashboard():
    if 'username' not in session or session['username'] not in sudo_users:
        return redirect('/login')

    # Load locked users from locked.csv
    try:
        with open('locked.csv', mode='r', encoding='utf-8') as locked_file:
            locked_users = set(locked_file.read().splitlines())
    except FileNotFoundError:
        locked_users = set()

    # Render the dashboard template with user data
    return render_template('dashboard.html', users=read_users(), sudo_users=sudo_users, restricted_users=restricted_users, posts=posts[::-1], locked_users=locked_users)



@app.route('/delete_user/<username>')
def delete_user(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return render_template('error.html', error_message="Vous n'etes pas administrateurs. (Tu n'as rien a foutre ici!!!)")

    users = read_users()
    if username in users:
        del users[username]
        with open('users.csv', mode='a', encoding='utf-8', newline='') as users_file:
            writer = csv.writer(users_file)
            for user, password in users.items():
                writer.writerow([user, password])
        DataClass.log_action(f"Deleted user: {username}")
    return redirect(url_for('dashboard'))

@app.route('/api/posts')
def get_posts():
    posts = read_posts()
    return jsonify([{'text': post[0], 'username': post[1], 'comments': post[2], 'image_url': post[3]} for post in posts])

@app.route('/api/users')
def get_users():
    users = read_users()
    return jsonify(list(users.items()))

@app.route('/api/search', methods=['GET'])
def search_yes():
    query = request.args.get('q', '')
    results = DataClass.search_posts(query)
    return jsonify([{'text': result['text'], 'username': result['user'], 'comments': result['comments'], 'image_url': result['image_url']} for result in results])

@app.route('/modify_sudo/<username>')
def modify_sudo(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return render_template('error.html', error_message="Vous n'etes pas administrateurs. (Tu n'as rien a foutre ici!!!)")

    if username in sudo_users:
        sudo_users.remove(username)
        action_message = f"Removed sudo privileges from user: {username}"
    else:
        sudo_users.add(username)
        action_message = f"Gave sudo privileges to user: {username}"

    with open('sudo.csv', 'w') as sudo_file:
        for sudo_user in sudo_users:
            sudo_file.write(sudo_user + '\n')

    DataClass.log_action(action_message)

    return redirect(url_for('dashboard'))


@app.route('/restrict_user/<username>')
def restrict_user(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return render_template('error.html', error_message="Vous n'etes pas administrateurs. (Tu n'as rien a foutre ici!!!)")

    if username in restricted_users:
        restricted_users.remove(username)
        action_message = f"Removed restrictions from user: {username}"
    else:
        restricted_users.add(username)
        action_message = f"Restricted user: {username}"

    with open('restricted.csv', 'w') as restricted_file:
        for restricted_user in restricted_users:
            restricted_file.write(restricted_user + '\n')

    DataClass.log_action(action_message)

    return redirect(url_for('dashboard'))

@app.route('/metadata/postid/<int:post_id>')
def metadata_postid(post_id):
    # Check if the user is logged in and is an administrator
    if 'username' not in session or session['username'] not in sudo_users:
        # Redirect to login page if not logged in or not an administrator
        return render_template('error.html', error_message="Vous n'etes pas administrateurs. (Tu n'as rien a foutre ici!!!)")

    # Ensure comments section exists and is a list[]
    # Save posts to CSV
    posts = []
    with open('posts.csv', mode='r') as file:
        reader = csv.reader(file)
        for i, row in enumerate(reader):
            if i == post_id:
                posts.append(row)
                break

    # Check if the posts list is empty
    if not posts:
        # Handle the case when no post with the specified ID is found
        return render_template('error.html', error_message="Post not found")

    # Assuming you have a bootstrap template for displaying posts
    return render_template('meta.html', posts=posts)

@app.route('/')
def home():
    if 'username' in session:
        if session['username'] in restricted_users:
            # Filter posts to show only the posts of the logged-in user
            user_posts = [post for post in posts if post[1] == session['username']]
            restricted_post = ["Vous êtes en mode restreint", session['username'], [], None]
            user_posts.append(restricted_post)
            return render_template('index.html', posts=user_posts)
    if 'username' not in session:
        return render_template('welcome.html')
    return render_template('index.html', posts=posts)

@app.route('/view-mode')
def home_view():
    return render_template('index.html',posts=posts)


@app.route('/signme/<usernama>')
def signit(usernama):
    input_file="signed.csv"
    variable_to_search = session['username']
    variable_to_write = usernama
    output_file = 'signed.csv'
    with open(input_file, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        lines = list(reader)

    found = False
    for line in lines:
        if variable_to_search in line[0]:
            line.extend([''] * max(0, 1 - len(line)))  # Ensure there's at least one element in row 1
            line[1] = variable_to_write
            found = True
            break

    if not found:
        # If search variable not found, create a new row and append it to the lines list
        new_row = [variable_to_search, variable_to_write]
        lines.append(new_row)

    with open(output_file, mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(lines)
    print("Variable written to signed.csv successfully.")


# Updated login route to check if the user is locked
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        recaptcha_secret = ''
        data = {
            'secret': recaptcha_secret,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()

        if not result['success']:
            return 'Veuillez compléter la vérification reCAPTCHA.'

        # Check if the user is locked
        if username in locked_users:
            return 'Ce compte est verrouillé. Contactez l\'administrateur pour plus d\'informations.'

        hashed_password = DataClass.hash_password(password)

        # Check credentials
        try:
            with open('users.csv', mode='r', encoding='utf-8') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username and row[1] == hashed_password:
                        session['username'] = username
                        DataClass.log_action(f"Logged in: {username}")
                        def write_username_to_csv(username):
                            filename = 'signed.csv'
                            with open(filename, mode='a', encoding='utf-8', newline='') as csvfile:
                                writer = csv.writer(csvfile)
                                writer.writerow([username])

                        # Example usage
                        # write_username_to_csv(username)


                        return redirect('/')
                return 'Nom d\'utilisateur ou mot de passe incorrect'
        except FileNotFoundError:
            return 'Fichier des utilisateurs introuvable.'

    return render_template('login.html')


# ... (existing code) ...



@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'username' in session:
        DataClass.log_action(f"Logged out: {session['username']}")
        session.pop('username', None)
    return redirect('/')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    def is_valid_username(username):
        # bad arch spagethi code........
      return True


    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Validate reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        recaptcha_secret = ''
        data = {
            'secret': recaptcha_secret,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()
        username = escape(username)
        if not result['success']:
            return 'Veuillez compléter la vérification reCAPTCHA.'
        if not is_valid_username(username):
            return f'Utilisateur Bloqué pour nom utilisateur "{username}" inapproprié. Veuillez réessayer avec un autre <a href="https://winternet.pythonanywhere.com/signup">ici.</a>'


        # Check if username is available
        try:
            with open('users.csv', 'r', encoding='utf-8') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username:
                        return 'Ce nom d\'utilisateur est déjà pris. Veuillez en choisir un autre.'

            # Add new user to users.csv
            with open('users.csv', mode='a', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([username, DataClass.hash_password(password)])

            # Log in the new user
            session['username'] = username

            DataClass.log_action(f"Signed up: {username}")

            return '''Bienvenue sur Winternet, une plateforme dédiée à la communication et à l'interaction entre ses utilisateurs. Avant d'utiliser nos services, veuillez lire attentivement les conditions d'utilisation suivantes: Contenu Inapproprié: 1.1. Tout contenu considéré comme (trop)raciste, (trop)sexiste, (trop)homophobe ou (trop)discriminatoire sera interdit sur notre plateforme. 1.2. Nous nous réservons le droit de supprimer tout contenu qui enfreint cette politique, sans préavis ni obligation de justification. Contenu Pornographique: 2.1. La diffusion de contenu pornographique est strictement interdite sur notre plateforme. 2.2. Tout contenu à caractère pornographique sera supprimé dès sa découverte. 2.3. Nous nous réservons le droit de prendre des mesures disciplinaires à l'égard des utilisateurs qui enfreignent cette politique, y compris la résiliation de leur compte. Responsabilité de l'Utilisateur: 3.1. Les utilisateurs sont responsables du contenu qu'ils publient sur notre plateforme. 3.2. En utilisant nos services, vous acceptez de ne pas publier de contenu offensant, illégal ou contraire à nos politiques. 3.3. Vous acceptez également de respecter les droits d'auteur et les droits de propriété intellectuelle des autres utilisateurs. Signalement de Contenu: 4.1. Nous encourageons les utilisateurs à signaler tout contenu inapproprié ou offensant qu'ils rencontrent sur notre plateforme. 4.2. Nous examinerons rapidement tous les signalements et prendrons les mesures appropriées. Modification des Conditions d'Utilisation: 5.1. Nous nous réservons le droit de modifier ces conditions d'utilisation à tout moment. 5.2. Les utilisateurs seront informés des changements via notre site Web ou par d'autres moyens appropriés. 5.3. En continuant à utiliser nos services après la publication des modifications, vous acceptez les nouvelles conditions d'utilisation. En utilisant nos services, vous reconnaissez avoir lu, compris et accepté les présentes conditions d'utilisation. Si vous ne les acceptez pas, veuillez ne pas utiliser notre plateforme. License GNU GPL v3. Si vous acceptez, veuillez vous rendre sur le <a href="https://winternet.pythonanywhere.com">Site Principal.</a>'''
        except FileNotFoundError:
            return 'Fichier des utilisateurs introuvable.'

    return render_template('signup.html')
@app.route('/subscribe/<username>', methods=['POST','GET'])
def subscribe(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Check if the logged-in user is already subscribed
    with open('subscriptions.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == session['username'] and row[1] == username:
                return "You are already subscribed to this user."

    # Add new subscription to subscriptions.csv
    with open('subscriptions.csv', 'a') as file:
        writer = csv.writer(file)
        writer.writerow([session['username'], username])

    return render_template('back.html')


@app.route('/my_feed')
def my_feed():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get the subscriptions of the logged-in user
    subscriptions = set()
    with open('subscriptions.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            print(f"Subscription row: {row}")
            if len(row) > 1 and row[0] == session['username']:
                subscriptions.add(row[1])

    # Get the liked hashtags of the logged-in user
    liked_hashtags = set()
    with open('likedhashtags.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) > 1 and row[0] == session['username']:
                liked_hashtags.update(json.loads(row[1]))

    # Get the posts of the users that the logged-in user is subscribed to and the users that they are subscribed to
    posts = []
    with open('posts.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) > 2 and (row[1] in subscriptions or any(hashtag in row[2] for hashtag in liked_hashtags)):
                posts.append(row)

    return render_template('my_feed.html', posts=posts)
@app.route('/add_liked_hashtags', methods=['GET', 'POST'])
def add_liked_hashtags():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_hashtags = request.form.get('hashtags')
        print(f"New hashtags input: {new_hashtags}")
        if new_hashtags:
            try:
                new_hashtags = [hashtag.strip() for hashtag in new_hashtags.split(',')]
                print(f"Parsed new hashtags: {new_hashtags}")
            except Exception as e:
                flash('Invalid format for hashtags')
                return redirect(url_for('add_liked_hashtags'))

            with open('likedhashtags.csv', mode='r+', encoding='utf-8') as file:
                reader = csv.reader(file)
                rows = list(reader)
                user_found = False
                for row in rows:
                    print(f"Liked hashtags row: {row}")
                    if len(row) > 1 and row[0] == session['username']:
                        current_hashtags = json.loads(row[1])
                        current_hashtags.extend(new_hashtags)
                        row[1] = json.dumps(list(set(current_hashtags)))  # Remove duplicates
                        user_found = True
                        break
                if not user_found:
                    rows.append([session['username'], json.dumps(new_hashtags)])
                file.seek(0)
                writer = csv.writer(file)
                writer.writerows(rows)
                file.truncate()

        return redirect(url_for('my_feed'))

    return render_template('add_liked_hashtags.html')

def get_subscribers(subscriptions):
    subscribers = set()
    with open('subscriptions.csv', mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[1] in subscriptions:
                subscribers.add(row[0])
    return subscribers


failed_attempts = {}

# Constants for timing (in seconds)
POST_LIMIT = 30
EXTENDED_LIMIT = 5 * 60
min_char=30

@app.route('/new_post', methods=['POST'])
def new_post():
    # Check if the user is logged in
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    current_time = time.time()

    # Check for posting limits
    if username in last_post_time:
        time_since_last_post = current_time - last_post_time[username]

        if failed_attempts.get(username, 0) >= 3:
            if time_since_last_post < EXTENDED_LIMIT:
                return render_template('error.html', error_message="You are restricted from posting for 5 minutes due to multiple attempts.")
            else:
                failed_attempts[username] = 0
        elif time_since_last_post < POST_LIMIT:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            if failed_attempts[username] >= 3:
                return render_template('error.html', error_message="You are now restricted for 5 minutes due to multiple attempts.")
            else:
                return render_template('error.html', error_message=f"Please wait {POST_LIMIT - int(time_since_last_post)} seconds before posting again.")

    # Process the post
    failed_attempts[username] = 0
    last_post_time[username] = current_time

    text = request.form.get('text')
    image = request.files.get('image')
    video = request.files.get('video')
    image_url = None

    if len(text.replace(" ", "")) < min_char:
        return render_template('error.html', error_message="Minimum 30 chars.")

    # Handle anonymous mode
    anonymous_mode = request.form.get('anonymous') == 'on'
    if anonymous_mode:
        username = "Anonyme"

    # Handle image upload
    if image:
        try:
            image_filename = secure_filename(image.filename)
            image_content = image.read()
            dbx.files_upload(image_content, f'/images/{image_filename}')
            image_url = f"https://winternet.pythonanywhere.com/media/{image_filename}"
        except Exception as e:
            return render_template('error.html', error_message=e)

    # Handle video upload
    if video:
        try:
            video_filename = secure_filename(video.filename)
            video_content = video.read()
            dbx.files_upload(video_content, f'/videos/{video_filename}')
            image_url = f"https://winternet.pythonanywhere.com/media/{video_filename}"
        except Exception as e:
            return render_template('error.html', error_message=e)

    # Save the post
    post = [text, username, [], image_url, 0, [], session['username']]
    posts.append(post)

    with open('posts.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(posts)

    DataClass.log_action(f"Added new post by: {username}")

    # Redirect to the "posting" page
    return redirect('/posting')
@app.route('/posting')
def posting():
    return render_template('posting.html')
def load_groups():
    """Load groups from CSV file."""
    if os.path.exists('groups.csv'):
        with open('groups.csv', mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            return list(reader)
    return []

groups = load_groups()

def save_groups():
    """Save groups to CSV file."""
    with open('groups.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(groups)

# Load group posts from CSV
def load_group_posts():
    """Load group posts from CSV file."""
    group_posts = []
    if os.path.exists('group_posts.csv'):
        with open('group_posts.csv', mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            group_posts = list(reader)
    return group_posts

# Load group members from CSV
def load_group_members():
    """Load group members from CSV file."""
    members = []
    if os.path.exists('group_members.csv'):
        with open('group_members.csv', mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            members = list(reader)
    return members

def save_group_members(members):
    """Save group members to CSV file."""
    with open('group_members.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(members)

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'username' not in session:
        return redirect('/login')

    group_name = request.form.get('group_name')
    description = request.form.get('description')
    group_type = request.form.get('group_type')  # 'public' or 'private'
    creator = session['username']

    group = [group_name, description, group_type, creator]
    groups.append(group)
    save_groups()

    # Automatically add the creator as a member of the group
    members = load_group_members()
    members.append([group_name, creator])
    save_group_members(members)

    return redirect('/groups')

@app.route('/groups')
def view_groups():
    if 'username' not in session:
        return redirect('/login')
    """Display all groups or search results."""
    query = request.args.get('query', '')
    filtered_groups = [group for group in groups if query.lower() in group[0].lower() or query.lower() in group[1].lower()]

    return render_template('groups.html', groups=filtered_groups, query=query)

@app.route('/group/<group_name>/')
def view_group(group_name):
    if 'username' not in session:
        return redirect('/login')
    """Display details of a specific group."""
    # Retrieve the group details
    group = next((g for g in groups if g[0] == group_name), None)
    if not group:
        return render_template('error.html', error_message="Group not found")

    # Access control: Check if the group is private and the user is not the creator or a member
    members = load_group_members()
    is_member = any(m[0] == group_name and m[1] == session.get('username') for m in members)
    if group[2] == 'private' and not is_member and session.get('username') != group[3]:
        return render_template('error.html', error_message="Vous ne pouvez pas acceder ce groupe. Il est privé.")

    # Load group posts
    group_posts = load_group_posts()
    group_posts_filtered = [post for post in group_posts if post[6] == group_name]
    group_posts_filtered.reverse()

    # Pass the group details to the template
    return render_template('group.html', group_name=group_name, group=group, posts=group_posts_filtered)


@app.route('/group/<group_name>/post', methods=['POST'])
def new_group_post(group_name):
    if 'username' not in session:
        return redirect('/login')

    group = next((g for g in groups if g[0] == group_name), None)
    if not group:
        return render_template('error.html', error_message="Group not found")

    # Access control: Check if the group is private and the user is not the creator or a member
    members = load_group_members()
    is_member = any(m[0] == group_name and m[1] == session.get('username') for m in members)
    if group[2] == 'private' and not is_member and session.get('username') != group[3]:
        return render_template('error.html', error_message="Vous ne pouvez pas acceder ce groupe. Il est privé.")

    group_posts = load_group_posts()
    text = request.form.get('text')
    username = session['username']
    image_url = None

    anonymous_mode = request.form.get('anonymous') == 'on'

    if anonymous_mode:
        username = "Anonyme"

    post = [text, username, [], image_url, 0, [], group_name]
    group_posts.append(post)

    with open('group_posts.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(group_posts)

    return redirect(f'/group/{group_name}')

@app.route('/group/<group_name>/add_member', methods=['POST'])
def add_member(group_name):
    """Add a user to a private group."""
    if 'username' not in session:
        return redirect('/login')

    group = next((g for g in groups if g[0] == group_name), None)
    if not group:
        return render_template('error.html', error_message="Group not found")

    # Only the creator can add members to the private group
    if session['username'] != group[3]:
        return render_template('error.html', error_message="Only the creator can add members.")

    new_member = request.form.get('new_member')
    members = load_group_members()

    # Check if the user is already a member
    if any(m[0] == group_name and m[1] == new_member for m in members):
        return render_template('error.html', error_message="User is already a member of the group.")

    members.append([group_name, new_member])
    save_group_members(members)

    return redirect(f'/group/{group_name}')

@app.route('/search_groups', methods=['GET'])
def search_groups():
    beta = True
    if beta:
        return render_template('error.html', error_message='La fonction est pas prete a être utilisée')
    """Route for searching groups."""
    query = request.args.get('query', '')
    results = [group for group in groups if query.lower() in group[0].lower() or query.lower() in group[1].lower()]

    return render_template('search.html', groups=results)



@app.route('/comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    if 'username' not in session:
        return redirect('/login')

    text = request.form.get('text')
    username = session['username']

    # Ensure comments section exists and is a list
    if len(posts[post_id]) < 3 or not isinstance(posts[post_id][2], list):
        posts[post_id][2] = []

    posts[post_id][2].append([text, username])

    # Save posts to CSV
    with open('posts.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(posts)

    DataClass.log_action(f"Added comment by: {username}")
    return render_template('back.html')
@app.route('/post/<int:post_id>')
def add(post_id):
    # Ensure comments section exists and is a list[]
    # Save posts to CSV
    with open('posts.csv', mode='r') as file:
        reader = csv.reader(file)
        for i, row in enumerate(reader):
            if i == post_id:
                break
    posts=[row]
    return render_template('post.html',posts=posts)
@app.route('/upvote/<int:post_id>', methods=['POST'])
def upvote(post_id):
    if 'username' not in session:
        return redirect('/login')

    username = session['username']

    # Check if username is in the list of users who have upvoted
    if isinstance(posts[post_id][5], str):
        upvotes_list = ast.literal_eval(posts[post_id][5])
    else:
        upvotes_list = posts[post_id][5]
    if session['username'] in posts[post_id][1]:
        return render_template('back.html')
    if username in upvotes_list:
        return render_template('back.html')  # or any other appropriate action

    posts[post_id][4] = str(int(posts[post_id][4]) + 1)
    upvotes_list.append(username)
    posts[post_id][5] = upvotes_list

    # Save posts to CSV
    with open('posts.csv', mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(posts)

    DataClass.log_action(f"Added upvote by: {username}")


    return render_template('back.html')
@app.route('/repost/<int:post_id>', methods=['POST'])
def repost(post_id):
    if 'username' not in session:
        return redirect('/login')

    username = session['username']

    # Check if post_id is valid
    if 0 <= post_id < len(posts):
        # Get original post details
        original_post = posts[post_id]

        # Create a new post with original post details but with the current user's username
        reposted_post = [original_post[0], username, original_post[2], original_post[3], 0, []]

        # Add the reposted post to the posts list
        posts.append(reposted_post)

        # Save updated posts to CSV
        with open('posts.csv', mode='a', encoding='utf-8', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(posts)

        DataClass.log_action(f"Reposted post by: {username}")

    return render_template('back.html')

@app.route('/delete_post/<int:post_id>', methods=['POST', 'GET'])
def delete_post(post_id):
    if 'username' not in session or session['username'] not in sudo_users:
        return render_template('error.html',
                               error_message='Vous ne disposez pas des priviléges necessaires pour supprimer un post. Seuls les administrateurs le peuvent.')

    # Check if post_id is valid
    if 0 <= post_id < len(posts):
        # Replace post content with "SUPPRIMÉ PAR username"
        posts[post_id] = ["SUPPRIMÉ PAR " + session['username'], "Modérateur", [], None, None]

        # Save modified posts to CSV
        with open('posts.csv', mode='a', encoding='utf-8', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(posts)

        DataClass.log_action(f"Deleted post by: {session['username']}")

    return render_template('back.html')
@app.route('/media/<filename>')
def media(filename):
    # Generate sharing link for the file
    try:
        try:
            shared_link = dbx.files_get_temporary_link(f'/images/{filename}').link
        except:
            shared_link = dbx.files_get_temporary_link(f'/videos/{filename}').link

    except Exception as e:
        return render_template('error.html', error_message=e)

    # Render a blank page with the embedded link
    return render_template('media.html', shared_link=shared_link)
if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=False, port=8000)
