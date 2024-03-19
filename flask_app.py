from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import csv
from werkzeug.utils import secure_filename
import dropbox
import datetime
import hashlib
def hash_password(password):
    """Hashes a password using SHA-256"""
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()
def hash_password2(password):
    """Hashes a password using SHA-256"""
    sha256 = hashlib.sha512()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()
app = Flask(__name__)
app.debug = True
app.secret_key = 'votre_clé_secrète'

#Set up Dropbox access token
DROPBOX_ACCESS_TOKEN = ''
key = ''
secret = ''
refresh = ''
#good luck with forums!!! for dropbox refresh

# Initialize Dropbox client
dbx = dropbox.Dropbox(
    app_key=key,
    app_secret=secret,
    oauth2_refresh_token=refresh
)

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

def read_users():
    try:
        with open('users.csv', 'r') as users_file:
            reader = csv.reader(users_file)
            users = {row[0]: row[1] for row in reader}
    except FileNotFoundError:
        users = {}
    return users


# Read posts from posts.csv
def read_posts():
    try:
        with open('posts.csv', 'r', newline='') as posts_file:
            reader = csv.reader(posts_file)
            posts = [row for row in reader]
    except FileNotFoundError:
        posts = []
    return posts


# Define a function to log actions
def log_action(action):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    user = session.get('username', 'Unknown')

    log_entry = f"{timestamp} - IP: {ip_address} - User: {user} - Action: {action} - User Agent: {user_agent} \n"

    with open('logs.txt', 'a') as log_file:
        log_file.write(log_entry)
@app.route('/api/login', methods=['POST'])
def api_login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Check if the user is locked
    if username in locked_users:
        return jsonify({"error": "This account is locked."}), 403

    password = hash_password(password)
    # Check credentials
    try:
        with open('users.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == username and row[1] == password:
                    session['username'] = username
                    log_action(f"Logged in: {username}")
                    return jsonify({"message": "User logged in successfully."})
            return jsonify({"error": "Incorrect username or password."}), 401
    except FileNotFoundError:
        return jsonify({"error": "User database not found."}), 500


@app.route('/api/logout', methods=['POST'])
def api_logout():
    if 'username' in session:
        log_action(f"Logged out: {session['username']}")
        session.pop('username', None)
    return jsonify({"message": "User logged out successfully."})


@app.route('/api/signup', methods=['POST'])
def api_signup():
    username = request.json.get('username')
    password = request.json.get('password')
    password = hash_password(password)
    # Check if username is available
    try:
        with open('users.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == username:
                    return jsonify({"error": "Username already taken."}), 400

        # Add new user to users.csv
        with open('users.csv', 'a') as file:
            writer = csv.writer(file)
            writer.writerow([username, password])

        # Log in the new user
        session['username'] = username

        log_action(f"Signed up: {username}")

        return jsonify({"message": "User signed up successfully."})
    except FileNotFoundError:
        return jsonify({"error": "User database not found."}), 500

# Route to handle serving media files
@app.route('/api/media/<filename>')
def api_media(filename):
    try:
        try:
            shared_link = dbx.files_get_temporary_link(f'/images/{filename}').link
        except:
            shared_link = dbx.files_get_temporary_link(f'/videos/{filename}').link

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"shared_link": shared_link})


@app.route('/api/delete_user/<username>', methods=['POST'])
def api_delete_user(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return jsonify({"error": "Unauthorized access."}), 403

    users = read_users()
    if username in users:
        del users[username]
        with open('users.csv', 'w', newline='') as users_file:
            writer = csv.writer(users_file)
            for user, password in users.items():
                writer.writerow([user, password])
        log_action(f"Deleted user: {username}")
    return jsonify({"message": "User deleted successfully."})


@app.route('/api/modify_sudo/<username>', methods=['POST'])
def api_modify_sudo(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return jsonify({"error": "Unauthorized access."}), 403

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

    return jsonify({"message": action_message})


@app.route('/api/restrict_user/<username>', methods=['POST'])
def api_restrict_user(username):
    if 'username' not in session or session['username'] not in sudo_users:
        return jsonify({"error": "Unauthorized access."}), 403

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

    return jsonify({"message": action_message})


@app.route('/api/')
def api_home():
    return jsonify({"message": "Welcome to the API."})


@app.errorhandler(404)
def page_not_found(error):
    return jsonify({"error": "Page not found."}), 404


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
        with open('posts.csv', 'w', newline='') as posts_file:
            writer = csv.writer(posts_file)
            writer.writerows(posts)

        log_action(f"Modified post at index {post_index}")

    return redirect(url_for('dashboard'))

# Route to handle lock/unlock action for a specific user
@app.route('/lock/<username>', methods=['POST'])
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
    return render_template('dashboard.html', users=read_users(), sudo_users=sudo_users, restricted_users=restricted_users, posts=posts, locked_users=locked_users)



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


# Updated login route to check if the user is locked
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user is locked
        if username in locked_users:
            return 'Ce compte est verrouillé. Contactez l\'administrateur pour plus d\'informations.'
        password = hash_password(password)
        # Check credentials
        try:
            with open('users.csv', 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username and row[1] == password:
                        session['username'] = username
                        log_action(f"Logged in: {username}")
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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password = hash_password(password)
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
                writer.writerow([username, password])

            # Log in the new user
            session['username'] = username

            log_action(f"Signed up: {username}")

            return redirect('/')
        except FileNotFoundError:
            return 'Fichier des utilisateurs introuvable.'

    return render_template('signup.html')


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

    post = [text, username, [], image_url]  # Add image and video URLs to post
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

    return redirect('/')


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

    return redirect('/')
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
    app.run(debug=True, port=8000)
