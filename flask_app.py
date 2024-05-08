#Dedicated to Igue Batiste, a friend in Sec 1.
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, Response, escape
import csv
from werkzeug.utils import secure_filename
import dropbox
import datetime
import hashlib 
import requests
import ast
import math
import cv2
import os
"""
Hashes a password using the SHA-256 algorithm.

Args:
    password (str): The password to be hashed.

Returns:
    str: The hashed password as a hexadecimal string.
"""
def hash_password(password):
    """Hashes a password using SHA-256"""
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()
def hash_password2(password):
    # Future hashing with SHA-512
    """Hashes a password using SHA-512"""
    sha512 = hashlib.sha512()
    sha512.update(password.encode('utf-8'))
    return sha512.hexdigest()
app = Flask(__name__)
app.debug = True
app.secret_key = 'votre_clé_secrète'
# Set up Dropbox access token
DROPBOX_ACCESS_TOKEN = ''
key = ''
secret = ''
refresh = ''
camera = cv2.VideoCapture(0)
# Initialize Dropbox client
dbx = dropbox.Dropbox(
    app_key=key,
    app_secret=secret,
    oauth2_refresh_token=refresh
)
# in advance, sorry for the messy code... At least you ll get a peak in the future...
# Read existing posts from CSV
try:
    with open('posts.csv', 'r', newline='') as file:
        reader = csv.reader(file)
        posts = []
        for row in reader:
            # Ensure the comments section is parsed as a list
            row[2] = eval(row[2])
            posts.append(row)
except FileNotFoundError:
    posts = []

try:
    with open('restricted.csv', 'r') as restricted_file:
        restricted_users = set(row.strip() for row in restricted_file)
except FileNotFoundError:
    restricted_users = set()

# Read sudo users from sudo.csv
try:
    with open('sudo.csv', 'r') as sudo_file:
        sudo_users = set(row.strip() for row in sudo_file)
except FileNotFoundError:
    sudo_users = set()
locked_users = set()

# Load locked users from locked.csv
try:
    with open('locked.csv', 'r') as locked_file:
        locked_users = set(locked_file.read().splitlines())
except FileNotFoundError:
    pass  # Handle the case where the file doesn't exist
# Read existing users from users.csv
"""
Reads user data from the 'users.csv' file and returns a dictionary mapping usernames to passwords.

If the 'users.csv' file is not found, an empty dictionary is returned.
"""
def read_users():
    try:
        with open('users.csv', 'r') as users_file:
            reader = csv.reader(users_file)
            users = {row[0]: row[1] for row in reader}
    except FileNotFoundError:
        users = {}
    return users


# Read posts from posts.csv
"""Reads the contents of the 'posts.csv' file and returns a list of post data.

If the 'posts.csv' file is not found, an empty list is returned.

Returns:
    list: A list of post data, where each element is a list representing a row from the 'posts.csv' file.
"""
def read_posts():
    try:
        with open('posts.csv', 'r', newline='') as posts_file:
            reader = csv.reader(posts_file)
            posts = [row for row in reader]
    except FileNotFoundError:
        posts = []
    return posts


# Define a function to log actions
"""
Logs an action to a text file.

This function logs an action to a text file named 'logs.txt'. It records the timestamp, IP address, username (if available), the action performed, and the user agent string.

Args:
    action (str): The action to be logged.
"""
def log_action(action):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    user = session.get('username', 'Unknown')

    log_entry = f"{timestamp} - IP: {ip_address} - User: {user} - Action: {action} - User Agent: {user_agent} \n"

    with open('logs.txt', 'a') as log_file:
        log_file.write(log_entry)
"""
Search for posts in the 'posts.csv' file that match the given query.

Args:
    query (str): The search query to match against post text and user names.

Returns:
    list[dict]: A list of dictionaries representing the matching posts, with keys for 'text', 'user', 'comments', and 'image_url'.
"""
def search_posts(query):
    results = []
    with open('posts.csv', 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            post_text = row[0].lower()
            user = row[1].lower()# Assuming post text is in the first column
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
"""
Generates a sitemap XML document for the Flask application.

The sitemap includes all routes in the application that have no arguments and can be accessed via GET requests. The sitemap is generated dynamically based on the application's URL map.

Returns:
    str: The sitemap XML document.
"""
@app.route('/search')
def search_page():
    query = request.args.get('q', '')
    post_results = search_posts(query)  # Search posts.csv for matching posts
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
"""
Ensures that the CSV file used to store pastebin entries exists and creates it with a header row if it does not.

The CSV file is used to store the server addresses and descriptions for pastebin entries. This code checks if the file exists, and if not, creates it with a header row to store the data.
"""
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        # Write the header row
        writer.writerow(['Server Address', 'Description'])

# Route for the pastebin
"""
Handles the pastebin functionality of the Flask application.

The `pastebin()` function is responsible for handling both the GET and POST requests for the pastebin page. When a GET request is received, it reads the server addresses and descriptions from a CSV file and renders the `pastebin.html` template with the data. When a POST request is received, it checks if the user is logged in, retrieves the server address and description from the form, and appends them to the CSV file.

The `view_paste()` function is responsible for rendering the `view_paste.html` template with the details of a specific pastebin entry, based on the provided index.
"""
@app.route('/pastebin', methods=['GET', 'POST'])
def pastebin():
    if request.method == 'POST':
        if 'username' not in session:
            return redirect(url_for('login'))
        # Get the server address and description from the form
        server_address = request.form.get('server_address')
        description = request.form.get('description')

        # Append the server address and description to the CSV file
        with open(CSV_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([server_address, description])
        # Redirect back to the pastebin page
        return redirect(url_for('pastebin'))

    # Read the server addresses and descriptions from the CSV file
    pastes = []
    with open(CSV_FILE, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            pastes.append(row)
    pastes.reverse()

    # Render the pastebin.html template and pass the pastes list
    return render_template('pastebin.html', pastes=pastes)
"""
Generates the sitemap.xml file for the Flask application.

This route is responsible for generating the sitemap.xml file, which is a file that
provides a structured list of the URLs on a website. The sitemap is used by search
engines to better understand the structure and content of the website, which can
improve the website's visibility in search results.

The `generate_sitemap()` function is called to generate the XML content for the
sitemap, and the resulting XML is returned as the response with the appropriate
content type.
"""
@app.route('/view_paste/<int:index>')
def view_paste(index):
    """
    Retrieves a specific pastebin entry from a CSV file based on the provided index.

    Args:
        index (int): The index of the pastebin entry to retrieve.

    Returns:
        str: The pastebin entry if the index is valid, or an error message and 404 status code if the index is invalid.
    """
    # Read the specific pastebin entry from the CSV file using the index
    pastes = []
    with open(CSV_FILE, 'r') as file:
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
@app.route('/sitemap.xml')
def sitemap():
    sitemap_xml = generate_sitemap()
    response = Response(sitemap_xml, mimetype='application/xml')
    return response
@app.route('/live_stream')
def live_stream():
    """
    Generates a live video stream response for the Flask application.
    
    This function is responsible for generating the frames of the live video stream and returning a Response object that can be used to stream the video to the client. The Response object is configured to use the 'multipart/x-mixed-replace; boundary=frame' content type, which allows the client to continuously receive new frames as they are generated.
    """
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')
@app.route('/start_stream')
def start_stream():
    """
    Starts the camera stream if it is not already open, and returns a message indicating the stream status.
    
    Returns:
        str: A message indicating whether the camera stream was started or is already running.
    """
    global camera
    if not camera.isOpened():
        camera = cv2.VideoCapture(0)
        return 'Camera stream started.'
    else:
        return 'Camera stream already started.'
PROFILE_FILE = 'profile.csv'

# Function to read profile data from CSV
"""
Reads a user profile from a CSV file.

Args:
    username (str): The username of the user whose profile should be read.

Returns:
    dict or None: A dictionary containing the user's profile information, or None if the user's profile is not found.
"""
def read_profile(username):
    with open(PROFILE_FILE, 'r') as file:
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
"""
Writes a user profile to a CSV file.

Args:
    profile (dict): A dictionary containing the user's profile information, including username, email, full name, and bio.

Returns:
    None
"""
def write_profile(profile):
    profiles = []
    with open(PROFILE_FILE, 'r') as file:
        reader = csv.reader(file)
        profiles = list(reader)

    with open(PROFILE_FILE, 'w', newline='') as file:
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
    """
    Renders the profile page for the given username.

    Args:
        username (str): The username of the user whose profile should be displayed.

    Returns:
        A rendered template for the profile page, or a rendered template for an error page if no profile is found.
    """
    profile = read_profile(username)
    if profile:
        return render_template('profile.html', profile=profile)
    else:
        return render_template('error.html',error_message='Pas de profil.')

# Route to edit a user's profile
@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    """
    Allows the user to edit their profile information, including email, full name, and bio.

    If the user is not logged in, they are redirected to the login page.

    When the user submits the edit profile form, the profile information is updated and the user is redirected to their profile page.
    """
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

@app.route('/stop_stream')
def stop_stream():
    """
Stops the camera stream and releases the camera resources.

Returns:
    str: A message indicating whether the camera stream was stopped or was already stopped.
"""
    global camera
    if camera.isOpened():
        camera.release()
        cv2.destroyAllWindows()
        return 'Camera stream stopped.'
    else:
        return 'Camera stream already stopped.'
"""
Generates a continuous stream of JPEG frames from the camera.

This function reads frames from the camera, encodes them as JPEG images, and yields them as a continuous stream of bytes. The function is designed to be used in a web application to display a live video feed.

Yields:
    bytes: A continuous stream of JPEG-encoded frames from the camera.
"""
def gen_frames():
    while True:
        success, frame = camera.read()
        if success:
            ret, buffer = cv2.imencode('.jpg', cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        else:
            break

@app.errorhandler(404)
def page_not_found(error):
    """
Handles the 404 error page for the Flask application.

This function is registered as the error handler for 404 errors. When a 404 error occurs, this function will be called to render the '404.html' template and return the response with a 404 status code.
"""
    return render_template('404.html'),404

@app.route('/send_message', methods=['POST'])
def send_message():
    """
Sends a message from the current user to the specified receiver.

If the user is not logged in, redirects to the login page.

Otherwise, retrieves the sender's username from the session, gets the receiver and message text from the form data, and appends a new message row to the 'messages.csv' file.

Finally, logs the action and redirects the user to the '/messages' route.
"""
    if 'username' not in session:
        return redirect('/login')

    sender = session['username']
    receiver = request.form.get('receiver')
    message_text = request.form.get('message_text')

    message = [sender, receiver, message_text]

    with open('messages.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(message)
    log_action(f"Sent message to {receiver}")
    return redirect('/messages')



@app.route('/messages')
def messages():
    """
Retrieves and displays the messages for the currently logged-in user.

This function reads the messages.csv file and returns a list of messages where the
current user's username is either the sender or the recipient. The messages are
then rendered in the messages.html template.

If the user is not logged in, they are redirected to the login page.
"""
    if 'username' not in session:
        return redirect('/login')

    messages = []
    with open('messages.csv', 'r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if session['username'].lower() in (row[0].lower(), row[1].lower()):
                messages.append(row)

    return render_template('messages.html', messages=messages)
@app.route('/new_messages', methods=['GET'])
def new_messages():
    """
Retrieves new messages that have been added since the last message ID provided.

If the user is not logged in, returns an empty list.

Otherwise, reads the messages.csv file and returns a list of new messages (rows from the file) where the message ID is greater than the last message ID provided.

Args:
    last_message_id (int): The ID of the last message the client has received.

Returns:
    list: A list of new messages as rows from the messages.csv file.
"""
    if 'username' not in session:
        return jsonify([])

    new_messages = []
    last_message_id = request.args.get('last_message_id', 0)

    with open('messages.csv', 'r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if int(row[3]) > int(last_message_id):
                new_messages.append(row)

    return jsonify(new_messages)
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error."}), 500

@app.route('/modify_post/<int:post_index>', methods=['POST'])
def modify_post(post_index):
    """
Modifies the details of a post in the application.

This function is responsible for updating the text, username, and image of a post in the application. It retrieves the post at the specified index, updates the relevant fields, and writes the updated posts back to the posts.csv file. The function also logs the action of modifying the post.

Args:
    post_index (int): The index of the post to be modified.

Returns:
    A redirect to the dashboard page.
"""
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
        with open('posts.csv', 'w', newline='') as posts_file:
            writer = csv.writer(posts_file)
            writer.writerows(posts)

        log_action(f"Modified post at index {post_index}")

    return redirect(url_for('dashboard'))

# Route to handle lock/unlock action for a specific user
@app.route('/lock/<username>', methods=['POST','GET'])
def toggle_lock(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return render_template('error.html', error_message="Vous n'êtes pas administrateurs. (Tu n'as rien à foutre ici!!!)")

    action = request.form.get('action')
    if action == 'lock':
        locked_users.add(username)
        log_action(f"Locked user: {username}")
    elif action == 'unlock':
        if username in locked_users:
            locked_users.remove(username)
            log_action(f"Unlocked user: {username}")

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
        with open('locked.csv', 'r') as locked_file:
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
        with open('users.csv', 'w', newline='') as users_file:
            writer = csv.writer(users_file)
            for user, password in users.items():
                writer.writerow([user, password])
        log_action(f"Deleted user: {username}")
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
    results = search_posts(query)
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

    log_action(action_message)

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

    log_action(action_message)

    return redirect(url_for('dashboard'))


@app.route('/')
def home():
    if 'username' in session:
        if session['username'] in restricted_users:
            # Filter posts to show only the posts of the logged-in user
            user_posts = [post for post in posts if post[1] == session['username']]
            restricted_post = ["Vous êtes en mode restreint", session['username'], [], None]
            user_posts.append(restricted_post)
            return render_template('index.html', posts=user_posts)
    return render_template('index.html', posts=posts)


# ... (existing code) ...

# New route to handle locking and unlocking

@app.route('/signme/<usernama>')
def signit(usernama):
    input_file="signed.csv"
    variable_to_search = session['username']
    variable_to_write = usernama
    output_file = 'signed.csv'
    with open(input_file, 'r') as file:
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

    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(lines)
    print("Variable written to signed.csv successfully.")

# Example usage:
# def signit(username,find=session['username']):
#     def write_up(username, find):
#         filename = 'signed.csv'
#         with open(filename, 'r', newline='') as csvfile:
#             reader = csv.reader(csvfile)
#             rows = list(reader)
#             row_index = -1  # Default index if not found
#             for i, row in enumerate(rows):
#                 if find in row:
#                     row_index = i
#                     break
#         with open(filename, 'w', newline='') as csvfile:
#             writer = csv.writer(csvfile)
#             for i, row in enumerate(rows):
#                 if i == row_index:
#                     writer.writerow([username])
#                 else:
#                     writer.writerow(row)
#     write_up(username)

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

        hashed_password = hash_password(password)

        # Check credentials
        try:
            with open('users.csv', 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username and row[1] == hashed_password:
                        session['username'] = username
                        log_action(f"Logged in: {username}")
                        def write_username_to_csv(username):
                            filename = 'signed.csv'
                            with open(filename, 'a', newline='') as csvfile:
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
        log_action(f"Logged out: {session['username']}")
        session.pop('username', None)
    return redirect('/')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    inappropriate_words = [
      # Profanity
      "fuck", "shit", "bitch", "cunt", "damn", "pussy", "ass", "asshole", "bastard", "dick", "crap", "hell",
      # Hate speech
      "nigger", "chink", "spic", "kike", "fag", "dyke", "sand nigger", "raghead", "porch monkey", "coon", "gook", "jap", 'nigga',
      # Sexual content
      "sex", "porn", "nude", "horny", "slut", "whore", "dildo", "vibrator", "anal", "oral", "blowjob", "handjob", "threesome", "orgy",
      # Violent content
      "kill", "murder", "rape", "torture", "death", "blood", "gore", "violence", "terrorism", "bomb", "gun", "shoot", "stab",
      # Illegal content
      "drugs", "weed", "crack", "meth", "heroin", "cocaine", "ecstasy", "lsd", "pot", "marijuana", "piracy", "warez", "torrent",
      # Offensive slurs
      "retard", "retarded", "gay", "queer", "homo", "lesbo", "tranny", "shemale", "fat", "ugly", "stupid", "idiot", "moron", "imbecile", "cripple"
    ]
    def is_valid_username(username):
      for word in inappropriate_words:
        if word in username:
          return False
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
            with open('users.csv', 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username:
                        return 'Ce nom d\'utilisateur est déjà pris. Veuillez en choisir un autre.'

            # Add new user to users.csv
            with open('users.csv', 'a') as file:
                writer = csv.writer(file)
                writer.writerow([username, hash_password(password)])

            # Log in the new user
            session['username'] = username

            log_action(f"Signed up: {username}")

            return '''Bienvenue sur Winternet, une plateforme dédiée à la communication et à l'interaction entre ses utilisateurs. Avant d'utiliser nos services, veuillez lire attentivement les conditions d'utilisation suivantes: Contenu Inapproprié: 1.1. Tout contenu considéré comme (trop)raciste, (trop)sexiste, (trop)homophobe ou (trop)discriminatoire sera interdit sur notre plateforme. 1.2. Nous nous réservons le droit de supprimer tout contenu qui enfreint cette politique, sans préavis ni obligation de justification. Contenu Pornographique: 2.1. La diffusion de contenu pornographique est strictement interdite sur notre plateforme. 2.2. Tout contenu à caractère pornographique sera supprimé dès sa découverte. 2.3. Nous nous réservons le droit de prendre des mesures disciplinaires à l'égard des utilisateurs qui enfreignent cette politique, y compris la résiliation de leur compte. Responsabilité de l'Utilisateur: 3.1. Les utilisateurs sont responsables du contenu qu'ils publient sur notre plateforme. 3.2. En utilisant nos services, vous acceptez de ne pas publier de contenu offensant, illégal ou contraire à nos politiques. 3.3. Vous acceptez également de respecter les droits d'auteur et les droits de propriété intellectuelle des autres utilisateurs. Signalement de Contenu: 4.1. Nous encourageons les utilisateurs à signaler tout contenu inapproprié ou offensant qu'ils rencontrent sur notre plateforme. 4.2. Nous examinerons rapidement tous les signalements et prendrons les mesures appropriées. Modification des Conditions d'Utilisation: 5.1. Nous nous réservons le droit de modifier ces conditions d'utilisation à tout moment. 5.2. Les utilisateurs seront informés des changements via notre site Web ou par d'autres moyens appropriés. 5.3. En continuant à utiliser nos services après la publication des modifications, vous acceptez les nouvelles conditions d'utilisation. En utilisant nos services, vous reconnaissez avoir lu, compris et accepté les présentes conditions d'utilisation. Si vous ne les acceptez pas, veuillez ne pas utiliser notre plateforme. License GNU GPL v3. Si vous acceptez, veuillez vous rendre sur le <a href="https://winternet.pythonanywhere.com">Site Principal.</a>'''
        except FileNotFoundError:
            return 'Fichier des utilisateurs introuvable.'

    return render_template('signup.html')
@app.route('/subscribe/<username>', methods=['POST','GET'])
def subscribe(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Check if the logged-in user is already subscribed
    with open('subscriptions.csv', 'r') as file:
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
    with open('subscriptions.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == session['username']:
                subscriptions.add(row[1])

    # Get the posts of the users that the logged-in user is subscribed to and the users that they are subscribed to
    posts = []
    with open('posts.csv', 'r') as file:
        reader = csv.reader(file)
        line_number = 0
        for row in reader:
            line_number += 1
            if row[1] in subscriptions or row[1] in get_subscribers(subscriptions):
                score = 1 / (1 + math.log(line_number))  # Use logarithmic score based on line number
                row.append(score)
                posts.append(row)

    # Apply a ranking algorithm to the posts
    ranked_posts = []
    for post in posts:
        score = post[-1]  # Use the score based on line number
        if post[1] in subscriptions:
            score += 2  # Additional score for being a post from a directly subscribed user
        ranked_posts.append((score, post))

    # Sort the posts by their scores
    ranked_posts.sort(reverse=True)

    # Extract the posts from the tuples
    ranked_posts = [post[:-1] for score, post in ranked_posts]

    return render_template('my_feed.html', posts=ranked_posts)

def get_subscribers(subscriptions):
    subscribers = set()
    with open('subscriptions.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[1] in subscriptions:
                subscribers.add(row[0])
    return subscribers




@app.route('/new_post', methods=['POST'])
def new_post():
    if 'username' not in session:
        return redirect('/login')

    text = request.form.get('text')
    username = session['username']
    image = request.files.get('image')
    video = request.files.get('video')  # Get the uploaded video file
    image_url = None

    # Upload image to Dropbox
    if image:
        try:
            image_filename = secure_filename(image.filename)
            image_content = image.read()
            dbx.files_upload(image_content, f'/images/{image_filename}')

            # Generate sharing link for the image
            image_shared_link = dbx.sharing_create_shared_link(f'/images/{image_filename}').url

            # Modify the image URL to use /media route
            image_url = f"https://winternet.pythonanywhere.com"+"/media/"+image_filename
        except Exception as e:
            return render_template('error.html', error_message=e)

    # Upload video to Dropbox
    if video:
        try:
            video_filename = secure_filename(video.filename)
            video_content = video.read()
            dbx.files_upload(video_content, f'/videos/{video_filename}')

            # Generate sharing link for the video
            video_shared_link = dbx.sharing_create_shared_link(f'/videos/{video_filename}').url

            # Modify the video URL to use /media route
            image_url = f'https://winternet.pythonanywhere.com'+"/media/"+video_filename
        except Exception as e:
            return render_template('error.html', error_message=e)

    post = [text, username, [], image_url,0,[]]  # Add image and video URLs to post
    posts.append(post)

    # Save new post to CSV
    with open('posts.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(posts)

    log_action(f"Added new post by: {username}")

    return redirect('/')


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
    with open('posts.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(posts)

    log_action(f"Added comment by: {username}")
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

    return redirect('/')
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

    if username in upvotes_list:
        return render_template('back.html')  # or any other appropriate action

    posts[post_id][4] = str(int(posts[post_id][4]) + 1)
    upvotes_list.append(username)
    posts[post_id][5] = upvotes_list

    # Save posts to CSV
    with open('posts.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(posts)

    log_action(f"Added upvote by: {username}")


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
        with open('posts.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(posts)

        log_action(f"Reposted post by: {username}")

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
        with open('posts.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(posts)

        log_action(f"Deleted post by: {session['username']}")

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
@app.route('/tor.snow')
def snow():
    return render_template('snow.html')
if __name__ == '__main__':
    app.run(debug=False, port=8000)
#Copyright Viktor Konkov 2024 version 2 Licensed GNU GPL v3
