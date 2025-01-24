# Winternet

## Overview
Winternet is a web application built using Flask. It is a social media framework meant to facilate access of self-hosting your own social media. It is minimal and includes no bloat whatsoever. I tested it on a 1 GHZ Pentium computer and it worked just fine. If you want to see it in live it is hosted here: https://winternet.pythonanywhere.com

## Features
- User authentication and session management
- Subscribe to other users
- Like hashtags
- View a feed of posts from subscriptions and liked hashtags

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/Winternet.git
    cd Winternet
    ```

2. Create a virtual environment and activate it:
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Set up environment variables:
    ```sh
    export FLASK_APP=flask_app.py
    export FLASK_ENV=development
    ```

5. Run the application:
    ```sh
    flask run
    ```

## Usage

- Navigate to `http://127.0.0.1:5000/` in your web browser or the host url.
- Register or log in to your account.
- Subscribe to other users and like hashtags.
- View your personalized feed.

## CSV Files

There is a long list of CSV files to create and manage, including:
- [likedhashtags.csv] Stores liked hashtags for users.
- [posts.csv]: Stores posts.
Here is the full list:
./locked.csv

./users.csv

./users.csv

./locked.csv

./profile.csv

./groups.csv

./posts.csv

./group_posts.csv

./users.csv

./messages.csv

./subscriptions.csv

./restricted.csv

./sudo.csv

./likedhashtags.csv

./videos.csv

./group_members.csv

./images.csv

./signed.csv

./servers.csv

./profile.csv

./groups.csv

./posts.csv

./group_posts.csv

./users.csv

./messages.csv

./subscriptions.csv

./restricted.csv

./sudo.csv

./likedhashtags.csv

./videos.csv

./group_members.csv

./images.csv

./signed.csv

./servers.csv
You will need to create these in the root directory
## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License

This project is licensed under the GPL 3.0 License. See the `LICENSE` file for more details.
