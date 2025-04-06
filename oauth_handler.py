from flask import Flask, request, redirect, session
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import os
import json
from datetime import datetime, timedelta
from functools import wraps
import config

app = Flask(__name__)
app.secret_key = config.SESSION_SECRET_KEY
app.permanent_session_lifetime = timedelta(seconds=config.SESSION_TIMEOUT)

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'last_request' in session:
            last_request = datetime.fromisoformat(session['last_request'])
            if datetime.now() - last_request < timedelta(seconds=1):
                return "Rate limit exceeded", 429
        session['last_request'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def create_oauth_flow():
    """Create and configure the OAuth flow."""
    flow = Flow.from_client_secrets_file(
        config.CLIENT_SECRETS_FILE,
        scopes=config.OAUTH_SCOPES,
        redirect_uri=config.REDIRECT_URI
    )
    return flow

@app.route('/')
@rate_limit
def index():
    """Start the OAuth flow."""
    flow = create_oauth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
@rate_limit
def oauth2callback():
    """Handle the OAuth callback."""
    if 'oauth_state' not in session:
        return "Invalid state parameter", 400
        
    flow = create_oauth_flow()
    
    try:
        # Get the authorization code from the callback
        flow.fetch_token(authorization_response=request.url)
        
        # Get credentials
        credentials = flow.credentials
        
        # Save encrypted credentials
        config.save_token('gmail_v1', credentials.to_json())
        
        # Clear session
        session.clear()
        
        return "Authentication successful! You can close this window."
    except Exception as e:
        return f"Authentication failed: {str(e)}", 400

def run_oauth_server():
    """Run the OAuth server."""
    app.run(host='localhost', port=8080)

if __name__ == '__main__':
    run_oauth_server() 