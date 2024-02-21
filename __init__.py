""" Plugin entry-point """

import json
import os
import re
import requests

from authlib.integrations.flask_client import OAuth

from CTFd.plugins import override_template
from CTFd.utils import get_app_config,get_config,set_config

from .blueprint import load_bp
from .models import OAuthClients
from flask import redirect, render_template,url_for
from CTFd.utils import user as current_user
from CTFd.utils.security.auth import logout_user

PLUGIN_PATH = os.path.dirname(__file__)
CONFIG = json.load(open("{}/config.json".format(PLUGIN_PATH)))

def oauth_clients():
    return OAuthClients.query.all()


def update_login_template(app):
    """
    Gets the actual login template and injects 
    the SSO buttons before the Forms.auth.LoginForm block
    """

    environment = app.jinja_environment
    original = app.jinja_loader.get_source(environment, 'login.html')[0]

    match = re.search(".*Forms\.auth\.LoginForm.*\n", original)

    # If Forms.auth.LoginForm is not found (maybe in a custom template), it does nothing
    if match:
        pos = match.start()

        PLUGIN_PATH = os.path.dirname(__file__)
        injecting_file_path = os.path.join(
            PLUGIN_PATH, 'templates/login_oauth.html')
        with open(injecting_file_path, 'r') as f:
            injecting = f.read()

        new_template = original[:pos] + injecting + original[pos:]
        override_template('login.html', new_template)


def load(app):

    def view_logout():
        if current_user.authed():
            logout_user()
            print("this is ",get_config("keycloak_user_logged"))

            if get_config("keycloak_user_logged") is None:
                print("Logging out")
                return redirect(url_for("views.static_html"))
            if get_config("keycloak_user_logged") == False:
                print("Logging out")
                return redirect(url_for("views.static_html"))
            

        #client_logout = get_config("keycloak_client_session")
        #print(client_logout)
        #logout_url="http://0.0.0.0:8080/realms/master/protocol/openid-connect/logout?"
        logout_url=get_config("current_keycloak_logout")
        
        from urllib.parse import quote
        #url_to_encode = "http://127.0.0.1:4000"
        url_to_encode = get_config("current_post_logout_redirect_uri")
        encoded_url = quote(url_to_encode,safe='')
        print(encoded_url)

        logout_url+="?post_logout_redirect_uri="
        logout_url+=encoded_url

        logout_url+="&id_token_hint="
        
        client_id=get_config("current_keycloak_id")

        client_secret=get_config("current_keycloak_secret")

        headers_logout = {"content_type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope" : "openid"
        }

        #token endpoint
        url=get_config("current_keycloak_token")
        
        token_request_logout = requests.post(url, data = data , headers=headers_logout)
        print("This is the token for logout ",token_request_logout.json())
        id_token_hint=token_request_logout.json()["id_token"]
        logout_url+=id_token_hint
        set_config("keycloak_user_logged",False)
        return redirect(logout_url)

    # The format used by the view_functions dictionary is blueprint.view_function_name
    app.view_functions['auth.logout'] = view_logout

    # Create database tables
    app.db.create_all()
    print("_________________________LOADING APP ")
    # Get all saved clients and register them
    
    clients = oauth_clients()
    oauth = OAuth(app)
    for client in clients:
        client.register(oauth)
    
    # Register oauth_clients() as template global
    app.jinja_env.globals.update(oauth_clients=oauth_clients)
    
    # Update the login template
    if bool(get_app_config("OAUTH_CREATE_BUTTONS")) == True:
        update_login_template(app)
    
    # Register the blueprint containing the routes
    bp = load_bp(oauth)
    print("skaw")
    print("app ",app)
    print("bp ",bp)

    app.register_blueprint(bp)
