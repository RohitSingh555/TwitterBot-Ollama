import base64
import hashlib
import os
import re
import json
import requests
import redis
from requests_oauthlib import OAuth2Session
from flask import request
from flask import Flask, redirect, session,jsonify
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy import desc
from flask import render_template
from flask_sqlalchemy import SQLAlchemy
import time 
from flask_migrate import Migrate, migrate
from werkzeug.utils import secure_filename
from openai import OpenAI, File
import asyncio
import tempfile
import shutil
from utils import *
from flask import render_template

#Global Variables
assistant_name = "Tweet Generator"

client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"
redirect_uri = os.environ.get("REDIRECT_URI")

scopes = ["tweet.read", "users.read","follows.read", "tweet.write", "offline.access"]

code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

api_key = os.environ.get("OPENAI_ID")
client = OpenAI(api_key=api_key)

app = Flask(__name__)
app.secret_key = os.urandom(50)
app.debug = True

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# DB Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    twitter_user_id = db.Column(db.Integer, unique=True, nullable=False )
    email = db.Column(db.String(120), unique=True, nullable=False)
    refresh_token = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(120), nullable=False)
    automate = db.Column(db.String(120), nullable=False, default="no")
    last_refreshed_on = db.Column(db.DateTime, nullable=True)
    username = db.Column(db.String(50), nullable=False)
    created = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified = db.Column(db.DateTime, default=db.func.current_timestamp(),
                         onupdate=db.func.current_timestamp())

class Assistant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assistant_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.twitter_user_id'), nullable=False)
    thread_id = db.Column(db.String(50), nullable=False)
    created = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified = db.Column(db.DateTime, default=db.func.current_timestamp(),
                         onupdate=db.func.current_timestamp())

class GPTResponses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response_tweet = db.Column(db.Text, nullable=True)
    response_tweet_id = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.twitter_user_id'), nullable=True)
    responded_to_tweet_id = db.Column(db.String(50), nullable=True)
    responded_to_tweet = db.Column(db.Text, nullable=True)
    responded_to_tweet_image_url = db.Column(db.Text, nullable=True)
    twitter_usernames = db.Column(db.Text, nullable=True)
    author_id = db.Column(db.String(50), nullable=True)
    created = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified = db.Column(db.DateTime, default=db.func.current_timestamp(),
                         onupdate=db.func.current_timestamp())
    

with app.app_context():
    db.create_all()

#Response instructions
instructions = '''
        You are A professional Human Like tweets Generator that responds to peoples tweets like a human being,
        Instructions for Generating Tweets:
        Direct Response: Each tweet generated should directly address the content or sentiment of the original user's tweet. The response should feel intuitive and connected to the conversation.
        Conciseness: Ensure the tweet is succinct and to the point. keeping the message clear without unnecessary details.
        Relevance: The response must be relevant and provide value in the context of the original tweet. Avoid digressing into unrelated topics or generic statements.
        No Advertisements: Do not include promotional content or advertisements. The focus should be on maintaining a natural and engaging interaction.
        Avoid Usernames: Do not include specific usernames (e.g., @user) in the tweet to maintain privacy and general applicability.
        Guidelines for Enhancing Tweet Quality:
        Clarity: Use clear and straightforward language. Avoid jargon unless it is appropriate for the tweet's context.
        Visuals: If applicable, suggest an image or emoji that complements the text. Visuals can enhance the message's impact and engagement.
        Hashtags: Integrate relevant hashtags to increase the visibility of the tweet. However, limit the use of hashtags to 1-2 to avoid clutter.
        Questions: Engage the audience by asking questions related to the original tweet. This encourages interaction and further discussion.
        Call-to-Action: Where appropriate, include a call-to-action that prompts users to engage further, such as asking for opinions, sharing the tweet, or visiting a link (ensure it is not promotional).
        Personalization: Tailor the tweet to reflect an understanding of the user's interests or past tweets, if available. This personal touch can increase engagement.
        Emojis: Use emojis to express emotions and add personality to the tweet, making it feel more human-like and relatable.
        Valuable Content: Ensure the tweet provides value, such as useful information, a thoughtful insight, or a helpful tip relevant to the original tweet's context.
        Always use the documents uploaded before answering. Always make sure that tweets should not exceed 260 characters in any case.
                                              '''

# custom error handler for 404 Not Found error
@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html'), 404

# custom error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html'), 500
# @app.errorhandler()
# def internal_server_error(error):
#     return render_template('error.html'), 500

# Refresh the token for cron job tasks
def refresh_token(client_id, client_secret, token_url, refresh_token):
    print("Refreshing Token!")
    headers = {
        "Authorization": "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode(),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    response = requests.post(token_url, headers=headers, data=data)
    print("Response after refreshing the token:", response.text)
    
    token = response.json()
    session["oauth_token"] = token
    return token

# defines scopes and just formats it
def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

# Post tweet functionalities
def post_tweet(payload, token):
    print("Tweeting!")
    return requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
    
@app.route('/post-reply', methods=['POST'])
def post_reply():
    data = request.json
    token = session.get("oauth_token")
    user_id = session.get('user_id')
    text = data.get('text')
    in_reply_to_tweet_id = data.get('reply', {})
    in_reply_to_tweet_id = in_reply_to_tweet_id.get('in_reply_to_tweet_id')
    print(in_reply_to_tweet_id)
    payload = {
        "text": text,
        "reply": {
            "in_reply_to_tweet_id": in_reply_to_tweet_id
        }
    }
    print("Tweeting!", payload)

    # Make the POST request
    response = requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
    # Check if the request was successful
    if response.ok:
        # Extract relevant data from response and return as JSON
        response_data = {
            'message': 'Reply posted successfully',
            'status_code': response.status_code,
            'response_body': response.json()  # Extract JSON response body
        }
        tweeted_tweet= response.json()
        tweet_id = tweeted_tweet['data']['id']
        existing_response = GPTResponses.query.filter_by(responded_to_tweet_id=in_reply_to_tweet_id).first()

        if existing_response:
            # Update the existing response
            existing_response.response_tweet_id = tweet_id
            existing_response.user_id = user_id

        db.session.commit()
            
        return jsonify(response_data)
    else:
        # If request failed, return an error message along with the status code
        return jsonify({'error': 'Failed to post reply', 'status_code': response.status_code})

# Get User Info API request 
def get_user_info(token):
    print("Getting UserID!")
    return requests.request(
        "GET",
        "https://api.twitter.com/2/users/me",
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
    
# Get Logged in user's following list from his/her twitter account 
def get_your_following_users(token,user_id):
    print("Getting your following!")
    print(user_id)
    print(token)
    return requests.request(
        "GET",
        "https://api.twitter.com/2/users/"+user_id+"/following",
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
    
# Get Logged in user's Timeline tweets reverse chronological(Latest ones)
def get_timeline_tweets(token,user_id,max_num):
    print("Getting Tweets!")
    return requests.request(
        "GET",
        "https://api.twitter.com/2/users/"+user_id+"/timelines/reverse_chronological?expansions=attachments.media_keys&max_results="+max_num,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
    
# Delete tweet that you have posted using post_reply api
@app.route('/delete_tweet', methods=['DELETE'])
def delete_tweet():
    user_id = session.get('user_id')
    token = session.get('oauth_token')['access_token']  # Extract the access token
    tweet_id = request.json.get('response_tweet_id')  # Use .get() to avoid KeyError

    print("delete tweet id,", tweet_id)
    print("delete token,", token)
    print("https://api.twitter.com/2/tweets/" + tweet_id)

    response = requests.request(
        "DELETE",
        "https://api.twitter.com/2/tweets/" + tweet_id,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )

    if response.status_code == 200:
        gpt_response = GPTResponses.query.filter_by(response_tweet_id=tweet_id).first()
        if gpt_response:
            db.session.delete(gpt_response)
            db.session.commit()
        return jsonify({'message': 'Tweet deleted successfully'}), 200
    else:
        return jsonify(response.json()), response.status_code
    
# Get Logged in user's Timeline tweets reverse chronological(Latest ones) But, with Cronjobs
def cron_get_timeline_tweets(token,user_id,max_num):
    print("Getting Tweets!")
    return requests.request(
        "GET",
        "https://api.twitter.com/2/users/"+user_id+"/timelines/reverse_chronological?expansions=attachments.media_keys&max_results="+max_num,
        headers={
            "Authorization": "Bearer {}".format(token),
            "Content-Type": "application/json",
        },
    )
    
# Get a particular user's tweets with the specified user's ID
def get_user_tweets(token,user_id):
    print("Getting Tweets!")
    return requests.request(
        "GET",
        "https://api.twitter.com/2/users/"+user_id+"/tweets",
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
    
# The Twitter authorization function that renders '/' url if assistant is created, else renders 'create-assistant'
@app.route("/twitter/login", methods=["GET"])
def callback():
    code = request.args.get("code")
    token = twitter.fetch_token(
        token_url=token_url,
        client_secret=client_secret,
        code_verifier=code_verifier,
        code=code,
    )
    response = get_user_info(token).json()
    print("response of twitter/login",response)
    user_id = response["data"]["id"]
    username = response["data"]["username"]
    session["username"] = username
    session["user_id"] = user_id
    print('Token --> ', token)
    print('username --> ', username)
    print('username --> ', user_id)
    session["oauth_token"] = token

    refresh_token_var=refresh_token(client_id, client_secret, token_url, token["refresh_token"])
    st_refreshed_token = '"{}"'.format(refresh_token_var)
    j_refreshed_token = json.loads(st_refreshed_token)
    
    isUserPresent=User.query.filter_by(username=username).first()
    if isUserPresent:
        print("User already exists. Updating...")
        isUserPresent.email = username
        isUserPresent.twitter_user_id = user_id
        isUserPresent.username = username
        isUserPresent.token = j_refreshed_token
        isUserPresent.refresh_token = j_refreshed_token
        db.session.commit()
    else:
        print("User not found. Adding new user...")
        user_insert = User(email=username,twitter_user_id=user_id, username=username,token=j_refreshed_token,refresh_token=j_refreshed_token)
        db.session.add(user_insert)
        db.session.commit()
    
    return redirect('/')

#Helps the user to create assistants before generating AI Responses
#Has three ways of creating assistants: Upload a file, Use your own tweets as your knowledge base, Use a follower's tweet as your knowledge base
@app.route("/create-assistant", methods=["GET"])
def assistant_form():
    token = session.get("oauth_token")
    user_id = session.get('user_id')
    responses = get_tweets_on_timeline(user_id)
    print("\\")
    print("twitter thing response following: ", responses)
    
    for response in responses:
        authorid = response['author_id']
        following_insert = GPTResponses(responded_to_tweet=response['text'],author_id=response['author_id'], twitter_usernames=response['username'],user_id=user_id,responded_to_tweet_id=response['id'])
        db.session.add(following_insert)
        db.session.commit()
    
    gpt_responses = GPTResponses.query.all()

    unique_author_ids = set()

    for response in gpt_responses:
        # Add the author ID and username as a tuple to the set
        unique_author_ids.add((response.author_id, response.twitter_usernames))

    # Convert the set of tuples to a list of dictionaries
    unique_author_data = [{"author_id": author_id, "twitter_usernames": username} for author_id, username in unique_author_ids]
    print(unique_author_data)

    return render_template("assistantform.html", gpt_responses=gpt_responses,unique_author_data=unique_author_data)

# The home page where feedback is taken and can be taken multiple times
@app.route("/")
async def demo():
    global twitter
    twitter = make_token()
    authorization_url, state = twitter.authorization_url(
        auth_url, code_challenge=code_challenge, code_challenge_method="S256"
    )
    
    if session.get('oauth_token'):
        user_id=session.get('user_id')
        isAssistantPresent=Assistant.query.filter_by(user_id=user_id).first()
        if isAssistantPresent :
            # tweets = await get_tweets_with_responses()
            AssistantPresent="yes"
        else:
            AssistantPresent="no"
            return redirect('/create-assistant')
        return render_template("response.html", AssistantPresent=AssistantPresent)
    return redirect(authorization_url)
        
#The user's timeline replica with Post reply and Regenerate AI response buttons 
@app.route("/timeline")
async def fetch_timeline_tweets():
    user_id = session.get('user_id')
    user = User.query.filter_by(twitter_user_id=user_id).first()
    if user and user.automate == 'yes':
        return redirect('/user-dashboard')
    else:
        if session.get('oauth_token'):
            user_id=session.get('user_id')
            
            isAssistantPresent=Assistant.query.filter_by(user_id=user_id).first()
            if isAssistantPresent :
                AssistantPresent="yes"
            else:
                AssistantPresent="no"
            print('Five tweets with resoponses --> ')
            print(time.time())
            return render_template("timeline.html",AssistantPresent=AssistantPresent)

# Find out the latest created time of the responses in GPT response table
def get_latest_gpt_response_time(user_id):
    latest_response = GPTResponses.query.filter_by(user_id=user_id).order_by(desc(GPTResponses.created)).first()
    return latest_response.created if latest_response else None


@app.route("/user-dashboard")
async def dashboard():
    if session.get('oauth_token'):
        user_id = session.get('user_id')
        
        # Check if the assistant is present
        isAssistantPresent = GPTResponses.query.filter_by(user_id=user_id).first()
        if isAssistantPresent:
            AssistantPresent = "yes"
        else:
            AssistantPresent = "no"
    
        # Fetch GPT responses
        gpt_responses = GPTResponses.query.filter_by(user_id=user_id).all()
        
        # Format the data
        response_data = []
        for response in gpt_responses:
            response_data.append({
                "response_tweet": response.response_tweet,
                "response_tweet_id": response.response_tweet_id,
                "responded_to_tweet_id": response.responded_to_tweet_id,
                "responded_to_tweet": response.responded_to_tweet,
                "responded_to_tweet_image_url": response.responded_to_tweet_image_url if response.responded_to_tweet_image_url else None,
                "twitter_usernames": response.twitter_usernames,
                "author_id": response.author_id,
                "created": response.created,
                "modified": response.modified
            })
        
        print('Five tweets with responses --> ')
        print(time.time())
        
        # Render the template with the data
        return render_template("dashboard.html", AssistantPresent=AssistantPresent, response_data=response_data)


# Find out the latest created time of the responses in GPT response table
# def get_latest_gpt_response_time(user_id):
#     latest_response = GPTResponses.query.filter_by(user_id=user_id).order_by(desc(GPTResponses.last_refreshed_on)).first()
#     return latest_response.created if latest_response else None

def get_last_refresh_time(user_id):
    latest_response = User.query.filter_by(twitter_user_id=user_id).order_by(desc(User.last_refreshed_on)).first()
    return latest_response.last_refreshed_on if latest_response else None

# Timeline tweets displaying functionality but, it's the one which reduces load time
@app.route('/db_tweets_on_timeline', methods=['GET'])
async def database_tweets_with_responses_on_timeline():
    # Get user ID and last refresh time
    user_id = session.get('user_id')
    last_refresh_time = get_last_refresh_time(user_id)
    tweets_with_responses = []

    # Check if last refresh time is within the last 15 minutes
    if last_refresh_time and (datetime.now() - last_refresh_time) < timedelta(minutes=15):
        # Fetch tweets and responses from the database
        tweets = GPTResponses.query.filter_by(user_id=user_id).all()
        for tweet in tweets:
            tweet_data = {
                "tweet": {
                    "author_id": tweet.author_id,
                    "id": tweet.responded_to_tweet_id,
                    "isFromDatabase": True,  
                    "text": tweet.responded_to_tweet,
                    "username": tweet.twitter_usernames 
                },
                "response": tweet.response_tweet
            }
            tweets_with_responses.append(tweet_data)
    else:
        # Update last refresh time
        user_response = User.query.filter_by(twitter_user_id=user_id).first()
        if user_response:
            user_response.last_refreshed_on = datetime.now()

        # Fetch tweets from an external source
        tweets = get_tweets_on_timeline(user_id)
        for tweet in tweets:
            # Check if response for tweet already exists in the database
            existing_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet['id']).first()
            if existing_response:
                tweets_with_responses.append({"tweet": tweet, "response": existing_response.response_tweet})
            else:
                # Fetch response from assistant
                assistant = Assistant.query.filter_by(user_id=user_id).first()
                if not assistant:
                    return jsonify({'error': 'Assistant not found for the user'}), 404
                
                originalTweet_Prompt=tweet['text']
                response = await get_agent_response(assistant.assistant_id, originalTweet_Prompt,user_id)
                response_for_tweet = response[0]
                try:
                    preview_image_url = tweet['preview_image_url']
                except:
                    preview_image_url = None
                
                # Create new entry in GPTResponses table
                gpt_response = GPTResponses(response_tweet=response_for_tweet, 
                                            responded_to_tweet_id=tweet['id'], 
                                            responded_to_tweet=tweet['text'],
                                            responded_to_tweet_image_url=preview_image_url,
                                            twitter_usernames=tweet['username'],
                                            author_id=tweet['author_id'],
                                            user_id=user_id)
                
                db.session.add(gpt_response)
                tweets_with_responses.append({"tweet": tweet, "response": response_for_tweet})

    # Commit changes to the database
    db.session.commit()        

    return tweets_with_responses


# Can delete this one, it's of no use as of now
def is_token_expired(expiry_time):
    current_time = time.time()
    return current_time >= expiry_time

# Get the detailed info of the tweets
def get_tweet_info(tweet_ids,token):
    # Twitter API endpoint URL
    url = "https://api.twitter.com/2/tweets"

    headers = {
    "Authorization": "Bearer " + token["access_token"]
}

    tweet_ids_str = ",".join(tweet_ids)

    params = {
        "ids": tweet_ids_str,
        "tweet.fields": "text,author_id,attachments,created_at", 
        "expansions": "attachments.media_keys,author_id",
        # "tweet.fields": ["created_at", "lang", "context_annotations","attachments"],
        # "user.fields": ["created_at", "description", "username"],
        "media.fields": "preview_image_url",
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status() 

        tweet_data = response.json()
        print("Tweet data: ", tweet_data)

        tweet_info_list = []
        users = tweet_data.get("includes", {}).get("users", {})

        for tweet in tweet_data.get("data", []):
            author_id = tweet.get("author_id")
            user = next((user for user in users if user.get("id") == author_id), {})
            
            tweet_info = {
                'id': tweet.get('id'),
                'text': tweet.get('text'),
                'author_id': author_id,
                'username': user.get('username'),
                'name': user.get('name'),
            }
            
            attachments = tweet.get('attachments', {})
            media_keys = attachments.get('media_keys', [])
            
            for media_key in media_keys:
                for media in tweet_data.get('includes', {}).get('media', []):
                    if media.get('media_key') == media_key:
                        preview_image_url = media.get('preview_image_url')
                        tweet_info['preview_image_url'] = preview_image_url
                        break
            
            tweet_info_list.append(tweet_info)
        return tweet_info_list

    except requests.exceptions.RequestException as e:
        print("Error fetching tweet:", e)
        return None
    
# Get tweets on the '/' URL
def get_tweets(user_id):
    token = session.get("oauth_token")
    tweets = [] 

    if token:
        response_data = get_timeline_tweets(token, user_id, "5").json()
        print("Response data:", response_data)

        if 'data' in response_data and response_data['data']:
            tweet_ids = [tweet['id'] for tweet in response_data['data']]
            print("Tweet IDs:", tweet_ids)
            
            try:
                tweets = get_tweet_info(tweet_ids, token)
            except Exception as e:
                print("An error occurred while fetching tweet information:", e)

        elif 'title' in response_data and response_data['title'] == 'Too Many Requests':
            print(f"Rate limit hit. Retry again...")

    else:
        print("OAuth token not available.")

    print("Printing...")
    return tweets

# Get tweets on Timeline (function not in use for timeline tweets)
def get_tweets_on_timeline(user_id):
    token = session["oauth_token"]
    if token:
        response_data = get_timeline_tweets(token, user_id,"5").json()
        

        if 'data' in response_data and response_data['data']:
            tweet_ids = [tweet['id'] for tweet in response_data['data']]
            # print("Tweet IDs:", tweet_ids)
            
            try:
                tweets = get_tweet_info(tweet_ids, token)
            except Exception as e:
                print("An error occurred while fetching tweet information:", e)

        elif 'title' in response_data and response_data['title'] == 'Too Many Requests':
            print(f"Rate limit hit. Retry again...")

    else:
        print("OAuth token not available.")
    
    print("Printing...")
    print("Response data:", tweets)
    return tweets


# Create Assistant sub functions:
# Uploads a file to Open AI and gets a file id as response
def upload_file_and_get_id(filename):
    file_ids = []
    with open(filename, "rb") as file:
            file_info = client.files.create(file=file, purpose='assistants')
            file_ids.append(file_info.id)
    
    return file_ids

# Takes the file id and creates an assistant for the user which helps the user to generate AI responses
def create_assistant_with_files(file_id):
    tools = [{"type":"code_interpreter"},
    {"type": "file_search"}]
    tool_resources = {
        'file_search': {
            'vector_stores': [{
                'file_ids': file_id
            }]
        }
    }
    assistant_data = {
        "name": assistant_name,
        "model": "gpt-4-turbo-2024-04-09",
        "instructions": instructions,
        "tools": tools,
        "tool_resources": tool_resources
    }
    try:
        assistant = client.beta.assistants.create(**assistant_data)
        return assistant
    except Exception as e:
        print(f"Error creating assistant: {e}")
        return None

# Saves the file as a temp file and generates it's path
def save_temp_file(input, filename):
    _, file_extension = os.path.splitext(filename)
    temp_file = tempfile.NamedTemporaryFile(suffix=file_extension, delete=False)
    shutil.copyfileobj(input, temp_file)
    temp_file_path = temp_file.name
    temp_file.close()
    return temp_file_path

# Creates the assistant and saves it into the database
@app.route('/create_assistant', methods=['POST'])
def create_assistant_route():
    selectYourTweets = request.form.get('selectYourTweets', 'off')
    Followed_users = request.form['twitter_user']
    Followed_users_list = [Followed_users]
    print("followed users:", Followed_users_list)
    file = request.files['uploadFile']
    user_id=session.get('user_id')
    token=session.get('oauth_token')
    if file: 
        filename = secure_filename(file.filename)
        path = save_temp_file(file, filename)
        file_id = upload_file_and_get_id(path)  # Upload file and get file ID
        
    if selectYourTweets == "on":
        response = get_user_tweets(token, user_id)
        tweets = response.json()
        print("create_assistant_route: Your tweets: ", tweets)
        
        # Create a temporary file to store the JSON data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write(json.dumps(tweets))
            temp_file_path = temp_file.name

        # Pass the temporary file to the upload_file_and_get_id function
        if temp_file_path:
            file_id = upload_file_and_get_id(temp_file_path)
            
    if Followed_users:
        responses = GPTResponses.query.filter(GPTResponses.author_id.in_(Followed_users_list)).all()
        tweets = [response.responded_to_tweet for response in responses] 
        
        print("create_assistant_route: Your tweets: ", json.dumps(tweets, indent=4))  
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            json.dump(tweets, temp_file)  
            temp_file_path = temp_file.name  

        if temp_file_path:
            file_id = upload_file_and_get_id(temp_file_path)
            print(f"Uploaded file ID: {file_id}")

    print("create_assistant_route: file_id: ",file_id)
    assistant = create_assistant_with_files(file_id)
    
    # Clean up the temporary file
    if temp_file_path:
        os.remove(temp_file_path)
    session["assistant_id"] = assistant.id
    thread=client.beta.threads.create()
    print("Thread ID-> ",thread.id)
    session["thread_id"] = thread.id
    isAssistantPresent=Assistant.query.filter_by(user_id=user_id).first()
    if isAssistantPresent :
        print("Present already")
    else:
        Assistant_insert= Assistant(assistant_id=assistant.id,user_id=user_id, thread_id=thread.id)
        db.session.add(Assistant_insert)
        db.session.commit()
    
    if assistant:
        return jsonify({'success': True, 'message': 'Assistant created successfully!', 'assistant_id': assistant.id})
    else:
        return jsonify({'success': False, 'message': 'Failed to create assistant.'})
    
# Runs a thread instance (can't run multiple threads for the same assistant simultaneously)
def handle_tool_outputs(run,thread_id):
    tool_outputs = []
    for call in run.required_action.submit_tool_outputs.tool_calls:
        function_name = call.function.name
        arguments = json.loads(call.function.arguments)
        output = function(**arguments)
        tool_outputs.append({"tool_call_id": call.id, "output": json.dumps(output)})

    user_thread_id = thread_id
    return client.beta.threads.runs.submit_tool_outputs(
        thread_id=user_thread_id,
        run_id=run.id,
        tool_outputs=tool_outputs
    )
    
# Gets AI responses and is the Main Gear function for getting the responses
async def get_agent_response(assistant_id, user_message, cron_user_id):
    print(" getting agent response: ", user_message, " assistant id ", assistant_id)
    user_id = session.get('user_id')
    if user_id:
        ThreadIdOfUser = Assistant.query.filter_by(user_id=user_id).first()
    else:
        ThreadIdOfUser = Assistant.query.filter_by(user_id=cron_user_id).first()
    print(" getting agent response: ThreadID-assistant ", ThreadIdOfUser)
    if ThreadIdOfUser:
        thread_id = ThreadIdOfUser.thread_id
    else:
        return "No corresponding thread found for the user ID."
    
    session["thread_id"] = thread_id
    
    client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=user_message,
    )

    # Create and run the interaction
    run = client.beta.threads.runs.create(
        thread_id=thread_id,
        assistant_id=assistant_id
    )

    # Wait for the run to complete
    while run.status in ["queued", "in_progress", "requires_action"]:
        if run.status == 'requires_action':
            run = handle_tool_outputs(run,thread_id)
        else:
            run = client.beta.threads.runs.retrieve(
              thread_id=thread_id,
              run_id=run.id
            )
            time.sleep(1)

    # Retrieve the last message in the thread
    last_message = client.beta.threads.messages.list(thread_id=thread_id, limit=1).data[0]

    # Check if the last message is from the assistant
    if last_message.role == "assistant":
        response_text = last_message.content[0].text.value
    else:
        response_text = "Error"
    return response_text, thread_id

# Function to receive prompts for creating responses
@app.route('/generate-response', methods=['POST'])
async def generate_response():
    user_id = session.get('user_id')
    
    data = request.get_json()
    tweet_id = data.get('id')
    tweet_text = data.get('text')
    tweet_text=tweet_text+" -> regenerate a better response for this tweet within 270 character limit of twitter."

    if not tweet_id or not tweet_text:
        return jsonify({'error': 'Tweet ID and text are required'}), 400

    assistant = Assistant.query.filter_by(user_id=user_id).first()
    if not assistant:
        return jsonify({'error': 'Assistant not found for the user'}), 404
        
    response = await get_agent_response(assistant.assistant_id, tweet_text,user_id)
    print("//// ")
    print("Regenerated response: ",response)
    print("//// ")
    response_for_tweet = response[0]
    
    gpt_response = GPTResponses(response_tweet=response_for_tweet, responded_to_tweet_id=tweet_id)
    db.session.add(gpt_response)
    db.session.commit()

    response = {"tweet_id": tweet_id, "response": response_for_tweet}
    
    return jsonify(response)

# gets tweets with responses for the home page(not in use for the home page)
async def get_tweets_with_responses():
    # Get tweets
    user_id = session.get('user_id')
    tweets = get_tweets(user_id)
    print("/////")
    print("timeline tweets: ",tweets)
    print("/////")
    tweets_with_responses = []
    for tweet in tweets:
        gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet['id']).first()
        if gpt_response:
            tweets_with_responses.append({"tweet": tweet, "response": gpt_response.response_tweet})
        else:
            assistant = Assistant.query.filter_by(user_id=user_id).first()
            if not assistant:
                return jsonify({'error': 'Assistant not found for the user'}), 404
            
            response =  await get_agent_response(assistant.assistant_id, tweet['text'],user_id)
            response_for_tweet = response[0]
            thread_id = response[1]
            
            gpt_response = GPTResponses(response_tweet=response_for_tweet, responded_to_tweet_id=tweet['id'])
            db.session.add(gpt_response)
            
            tweets_with_responses.append({"tweet": tweet, "response": response_for_tweet})
    db.session.commit()        
    return tweets_with_responses

# The modified function which reduces the load time and fetches the tweets for the first time after assistant is created
@app.route('/db_tweet_responses')
async def database_tweets_with_responses():
    user_id = session.get('user_id')
    tweets = GPTResponses.query.filter_by(user_id=user_id).order_by(GPTResponses.created.desc()).limit(5).all()
    tweets_with_responses = []
    # print("tweets from db --> ")
    # print(tweets)
    for tweet in tweets:
        assistant = Assistant.query.filter_by(user_id=user_id).first()
        if not assistant:
            return jsonify({'error': 'Assistant not found for the user'}), 404
        
        gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet.responded_to_tweet_id).first()

        if gpt_response and gpt_response.response_tweet:
            # If it exists and response_tweet is not null, use the existing response
            response_for_tweet = gpt_response.response_tweet
        else:
            # If it doesn't exist or response_tweet is null, create a new GPTResponses object and add it to the session
            originalTweet_Prompt=tweet.responded_to_tweet
            response = await get_agent_response(assistant.assistant_id, originalTweet_Prompt,user_id)
            response_for_tweet = response[0]
            thread_id = response[1]
            
            if not gpt_response:
                # If gpt_response does not exist, create a new one
                gpt_response = GPTResponses(
                    response_tweet=response_for_tweet,
                    responded_to_tweet_id=tweet.responded_to_tweet_id,
                    responded_to_tweet_image_url="",  
                    twitter_usernames=""  
                )
                db.session.add(gpt_response)
            else:
                # If gpt_response exists but response_tweet was null, update it
                gpt_response.response_tweet = response_for_tweet
        tweets_with_responses.append({
            "tweet": {
                'original_tweet': tweet.responded_to_tweet, 
                'response_tweet_id': tweet.responded_to_tweet_id
            }, 
            "response": response_for_tweet,
            "image_url": gpt_response.responded_to_tweet_image_url,
            "twitter_usernames": gpt_response.twitter_usernames
        })

        print('tweets with responses array --> ', tweets_with_responses)
    db.session.commit()        
    return jsonify(tweets_with_responses)

# gets tweets with responses on the timeline page and also saves them to GPTResponses table
async def get_tweets_with_responses_on_timeline():
    # Get tweets
    user_id = session.get('user_id')
    tweets = get_tweets_on_timeline(user_id)
    
    tweets_with_responses = []
    for tweet in tweets:
        gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet['id']).first()
        if gpt_response:
            tweets_with_responses.append({"tweet": tweet, "response": gpt_response.response_tweet})
        else:
            assistant = Assistant.query.filter_by(user_id=user_id).first()
            if not assistant:
                return jsonify({'error': 'Assistant not found for the user'}), 404
            
            response =  await get_agent_response(assistant.assistant_id, tweet['text'],user_id)
            response_for_tweet = response[0]
            thread_id = response[1]
            try:
                preview_image_url=tweet['preview_image_url']
            except:
                preview_image_url=None
            gpt_response = GPTResponses(response_tweet=response_for_tweet, responded_to_tweet_id=tweet['id'], responded_to_tweet=tweet['text'],responded_to_tweet_image_url=preview_image_url,twitter_usernames=tweet['username'],author_id=tweet['author_id'])
            db.session.add(gpt_response)
            
            tweets_with_responses.append({"tweet": tweet, "response": response_for_tweet})
    db.session.commit()        
    return tweets_with_responses

# Records the user's feedbacks and generates the responses according to the feedback
@app.route('/get_feedback_tweets_with_responses', methods=['POST'])
async def get_feedback_tweets_with_responses():
    request_data = request.json
    tweets_data = request_data.get('tweetsData', [])
    user_id = session.get('user_id')
    feedback_tweets_with_responses = []
    assistant = Assistant.query.filter_by(user_id=user_id).first()
    
    for tweet_data in tweets_data:
        tweet_text = tweet_data.get('originalText', '')
        tweet_id = tweet_data.get('id', '')
        ai_response_text = tweet_data.get('aiResponse', '')  
        feedback = tweet_data.get('feedback', '')  
        
        passing_data=f"This is the Original tweet: {tweet_text} \n we had an AI response for it: {ai_response_text} \n. Regenerate a response based on the feedback: {feedback}. keep assistant instructions in mind while generating the response and make sure the character count is less than 280 characters Long"
        # print("//// ")
        # print(passing_data)
        response_for_tweet = await get_agent_response(assistant.assistant_id, passing_data,user_id)
        response_for_tweet = response_for_tweet[0]
        # print("//// ")
        # print("feedback responses: ",response_for_tweet)
        # print("//// ")
        gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet_id).first()

        if gpt_response:
            gpt_response.response_tweet = response_for_tweet
        else:
            gpt_response = GPTResponses(response_tweet=response_for_tweet, responded_to_tweet_id=tweet_id)
            db.session.add(gpt_response)
        
        feedback_tweets_with_responses.append({"tweet": {'id': tweet_id, 'text': tweet_text}, "response": response_for_tweet}) 
    print("feedback with response: ",feedback_tweets_with_responses)
    db.session.commit()

    return jsonify(feedback_tweets_with_responses)

# The cron job functionality which is but a naive solution for now.
# Runs a loop on user table and posts the replies after generating a response and saving it to the database.
# tweets_posted_count = {}
@app.route('/cron-job')
async def cron_schedule_tweets():
    # Get all twitter_user_ids from the User model
    twitter_user_ids = [user.twitter_user_id for user in User.query.all()]
    
    for twitter_user_id in twitter_user_ids:
        user = User.query.filter_by(twitter_user_id=twitter_user_id).first()
        if user and user.automate == 'yes':
            user_refresh_token_str = user.refresh_token

            user_refresh_token_json = user_refresh_token_str.replace("'", '"')
# to extract token values from  the refresh token
            try:
                user_refresh_token_dict = json.loads(user_refresh_token_json)

                refresh_token_value = user_refresh_token_dict.get('refresh_token')

                if refresh_token_value:
                    print("Refresh token:", refresh_token_value)
                else:
                    print("Refresh token not found in JSON data")
            except json.JSONDecodeError as e:
                print("Error decoding JSON data:", e)

            # Now you can use user_refresh_token directly
            refresh_token_var = refresh_token(client_id, client_secret, token_url, refresh_token_value)
            st_refreshed_token = '"{}"'.format(refresh_token_var)
            # Convert the string back to a dictionary
            j_refreshed_token = json.loads(st_refreshed_token)
            isUserPresent = User.query.filter_by(username=user.username).first()
            # print(isUserPresent)
            if isUserPresent:
                print("User already exists. Updating...")
                isUserPresent.twitter_user_id = user.twitter_user_id
                isUserPresent.token = j_refreshed_token
                isUserPresent.refresh_token = j_refreshed_token
                db.session.commit()
            else:
                print("User not found. Adding new user...")
                user_insert = User(twitter_user_id=user.twitter_user_id, token=j_refreshed_token, refresh_token=j_refreshed_token)
                db.session.add(user_insert)
                db.session.commit()
                
                # converting the user token into a token value that can be used for api requests
            access_user_refresh_token_json = j_refreshed_token.replace("'", '"')
            try:
                access_user_refresh_token_dict = json.loads(access_user_refresh_token_json)

                access_refresh_token_value = access_user_refresh_token_dict.get('access_token')

                if access_refresh_token_value:
                    print("Refresh token:", access_refresh_token_value)
                else:
                    print("Refresh token not found in JSON data")
            except json.JSONDecodeError as e:
                print("Error decoding JSON data:", e)
            
            
            users_id=str(user.twitter_user_id)
            cron_responses = await cron_get_tweets_with_responses_on_timeline(users_id,access_refresh_token_value)
            if cron_responses:
            # print("cron responses: " , cron_responses)
            # print("These are the cron responses: ",cron_responses)
                for tweet_data in cron_responses:
                    in_reply_to_tweet_id = tweet_data['tweet']['id']  
                    response_text = tweet_data['response']
                    responded_to_tweet_id = tweet_data['responded_to_tweet_id']

                    isResponded = GPTResponses.query.filter_by(responded_to_tweet_id=responded_to_tweet_id).first()
                    author_id=tweet_data['tweet']['id']
                    # Check if isResponded is None before accessing its attributes
                    # if not author_id == isResponded.author_id:
                    if "Error" in response_text:
                        print("Error occurred while processing the Ai response (Probably due to Zero funds in you Open AI): ", response_text)
                        # Handle the error condition here if needed
                    elif len(response_text) < 20:
                        print("Response text is too short:", response_text)
                    else:
                        if isResponded is not None and isResponded.response_tweet_id:
                            print(isResponded.response_tweet_id, " is already present.")
                        else:
                            payload = {
                                "text": response_text,
                                "reply": {
                                    "in_reply_to_tweet_id": in_reply_to_tweet_id
                                }
                            }
                            # print(payload)

                            response = requests.post(
                                "https://api.twitter.com/2/tweets",
                                json=payload,
                                headers={
                                    "Authorization": "Bearer " + access_refresh_token_value,  
                                    "Content-Type": "application/json",
                                },
                            )
                            tweeted_tweet = response.json()
                            print("tweeted_data: ", tweeted_tweet)

                            if response.ok:
                                tweet_id = tweeted_tweet['data']['id']
                                existing_response = GPTResponses.query.filter_by(responded_to_tweet_id=responded_to_tweet_id).first()
                                # print(existing_response)
                                if existing_response:
                                    # Update the existing response
                                    print("/////")
                                    existing_response.response_tweet_id = tweet_id
                                    existing_response.response_tweet=response_text
                                print("Reply posted successfully!")
                            else:
                                print("Failed to post reply. Status code:", response.status_code)
        db.session.commit()

    return jsonify({"message": "Cron job executed successfully"})

# Gets timeline tweets for cron job and can be modified later
async def cron_get_tweets_with_responses_on_timeline(user_id, token):
    tweets = cron_get_tweets_on_timeline(user_id, token)
    tweets_with_responses = []

    for tweet in tweets:
        if tweet['author_id'] != user_id:
            gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet['id']).first()
            responded_to_tweet_id = tweet['id']
            
            if gpt_response and gpt_response.response_tweet:
                # Existing response is valid
                tweets_with_responses.append({"tweet": tweet, "response": gpt_response.response_tweet, "responded_to_tweet_id": responded_to_tweet_id})
            else:
                assistant = Assistant.query.filter_by(user_id=user_id).first()
                if not assistant:
                    return jsonify({'error': 'Assistant not found for the user'}), 404
                
                try:
                    response = await get_agent_response(assistant.assistant_id, tweet['text'], user_id)
                    response_for_tweet = response[0]
                    thread_id = response[1]
                except Exception as e:
                    print("Error generating response:", e)
                    continue  # Skip to the next tweet

                try:
                    preview_image_url = tweet.get('preview_image_url', None)
                except Exception as e:
                    print("Error getting preview image URL:", e)
                    preview_image_url = None

                if gpt_response:
                    # Update existing entry
                    gpt_response.response_tweet = response_for_tweet
                    gpt_response.responded_to_tweet_id = tweet['id']
                    gpt_response.responded_to_tweet = tweet['text']
                    gpt_response.responded_to_tweet_image_url = preview_image_url
                    gpt_response.twitter_usernames = tweet['username']
                    gpt_response.author_id = tweet['author_id']
                    gpt_response.user_id = tweet['author_id']
                else:
                    # Create a new entry
                    gpt_response = GPTResponses(
                        response_tweet=response_for_tweet,
                        responded_to_tweet_id=responded_to_tweet_id,
                        responded_to_tweet=tweet['text'],
                        responded_to_tweet_image_url=preview_image_url,
                        twitter_usernames=tweet['username'],
                        author_id=tweet['author_id'],
                        user_id=tweet['author_id']
                    )
                    db.session.add(gpt_response)

                tweets_with_responses.append({"tweet": tweet, "response": response_for_tweet, "responded_to_tweet_id": responded_to_tweet_id})

                try:
                    db.session.commit()
                    print("Database commit successful.")
                except Exception as e:
                    db.session.rollback()
                    print("Error committing to the database:", e)
        else:
            print("Tweet is by the user, no response generated.")

    if tweets_with_responses:
        return tweets_with_responses
    else:
        print("No new tweets to respond to.")
        return []


def cron_get_tweets_on_timeline(user_id,token):
    if token:
        response_data = cron_get_timeline_tweets(token, user_id,"6").json()
        # print("cron_response_data: " , response_data)

        if 'data' in response_data and response_data['data']:
            tweet_ids = [tweet['id'] for tweet in response_data['data']]
            # print("Tweet IDs:", tweet_ids)
            
            try:
                tweets = get_tweet_info_cron(tweet_ids, token)
                print(tweets)
            except Exception as e:
                print("An error occurred while fetching tweet information:", e)

        elif 'title' in response_data and response_data['title'] == 'Too Many Requests':
            print(f"Timeline Rate limit hit. Retry again...")

    else:
        print("OAuth token not available.")
    
    print("Printing...")
    print("Response data:", tweets)
    return tweets

def get_tweet_info_cron(tweet_ids,token):
    # Twitter API endpoint URL
    url = "https://api.twitter.com/2/tweets"

    headers = {
    "Authorization": "Bearer " + token
}

    tweet_ids_str = ",".join(tweet_ids)

    params = {
        "ids": tweet_ids_str,
        "tweet.fields": "text,author_id,attachments,created_at", 
        "expansions": "attachments.media_keys,author_id",
        "media.fields": "preview_image_url",
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status() 

        tweet_data = response.json()
        # print("Cron Tweet data: ", tweet_data)

        tweet_info_list = []
        users = tweet_data.get("includes", {}).get("users", {})

        for tweet in tweet_data.get("data", []):
            author_id = tweet.get("author_id")
            user = next((user for user in users if user.get("id") == author_id), {})
            
            tweet_info = {
                'id': tweet.get('id'),
                'text': tweet.get('text'),
                'author_id': author_id,
                'username': user.get('username'),
                'name': user.get('name'),
            }
            
            attachments = tweet.get('attachments', {})
            media_keys = attachments.get('media_keys', [])
            
            for media_key in media_keys:
                for media in tweet_data.get('includes', {}).get('media', []):
                    if media.get('media_key') == media_key:
                        preview_image_url = media.get('preview_image_url')
                        tweet_info['preview_image_url'] = preview_image_url
                        break
            
            tweet_info_list.append(tweet_info)
            # print(" tweet_info: ", tweet_info)

        return tweet_info_list

    except requests.exceptions.RequestException as e:
        print("Error fetching tweet:", e)
        return None
    
# Toggle to automate tweet posting on twitter account
@app.route('/toggle_automate', methods=['GET', 'POST'])
def toggle_automate():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    user = User.query.filter_by(twitter_user_id=user_id).first()

    if request.method == 'GET':
        return jsonify({'automate': user.automate})

    if request.method == 'POST':
        data = request.json
        new_automate_value = 'yes' if data.get('automate') else 'no'
        user.automate = new_automate_value
        db.session.commit()
        return jsonify({'message': 'Automate status updated successfully'})
    
    
# the main function which decides the port our function will run on
if __name__ == "__main__":
    app.run(port=3000,debug=True)