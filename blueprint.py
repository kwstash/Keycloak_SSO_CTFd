import requests
from flask import Blueprint, redirect, render_template, request, url_for ,session
from wtforms import StringField
from wtforms.validators import InputRequired

from CTFd.utils.modes import TEAMS_MODE

from CTFd.cache import clear_user_session
from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.models import Users,db
from CTFd.utils import get_app_config , set_config ,get_config
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.decorators import admins_only
from CTFd.utils.helpers import error_for
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user
from CTFd.cache import cache , clear_standings



from .models import OAuthClients

plugin_bp = Blueprint('sso', __name__, template_folder='templates', static_folder='static', static_url_path='/static/sso')


class OAuthForm(BaseForm):
    name = StringField("Client name", validators=[InputRequired()])
    client_id = StringField("OAuth client id", validators=[InputRequired()])
    client_secret = StringField("OAuth client secret", validators=[InputRequired()])
    access_token_url = StringField("Access token url", validators=[InputRequired()])
    authorize_url = StringField("Authorization url", validators=[InputRequired()])
    api_base_url = StringField("User info url", validators=[InputRequired()])
    logout_url = StringField("Logout url", validators=[InputRequired()])
    post_logout_redirect_uri = StringField("Post-Logout Redirect uri", validators=[InputRequired()])
    submit = SubmitField("Apply")

def load_bp(oauth):

    @plugin_bp.route('/admin/sso')
    @admins_only
    def sso_list():
        return render_template('list.html')

    def sso_create():
        return render_template('create.html')
    
    
    @plugin_bp.route('/admin/sso/client/<int:client_id>', methods = ['GET', 'DELETE','POST'])
    @admins_only
    def sso_details(client_id):

        if request.method == 'DELETE':
            client = OAuthClients.query.filter_by(id=client_id).first()
            if client:
                client.disconnect(oauth)
                db.session.delete(client)
                db.session.commit()
                db.session.flush()
            return redirect(url_for('sso.sso_list'))
        if request.method == 'GET':
            print("-----------------------------------------------------------------------")
            print("-----------------------------------------------------------------------")
            print("Client you called was  ---", client_id)
            print("-----------------------------------------------------------------------")
            print("-----------------------------------------------------------------------")
            form = OAuthForm()
            client = OAuthClients.query.filter_by(id=client_id).first()
            return render_template('create.html', form=form ,client=client, client_id_mod=client_id , modify_client=True)
        if request.method == "POST":

            modify_client = request.form["modify_client"] #flag for updating information
            client_id_mod = request.form["client_id_mod"] #ID that needs to be changed
            print("Can I modify ? ---", modify_client)
            print("The client to do that to is  ", client_id_mod)
            #akeep the same id
            name = request.form["name"]
            client_id = request.form["client_id"]
            client_secret = request.form["client_secret"]
            access_token_url = request.form["access_token_url"]
            authorize_url = request.form["authorize_url"]
            api_base_url = request.form["api_base_url"]
            logout_url = request.form["logout_url"]
            post_logout_redirect_uri = request.form["post_logout_redirect_uri"]
            
            client = OAuthClients(
                name=name,
                #keep the same id 
                client_id=client_id,
                client_secret=client_secret,
                access_token_url=access_token_url,
                authorize_url=authorize_url,
                api_base_url=api_base_url,
                logout_url=logout_url,
                post_logout_redirect_uri=post_logout_redirect_uri
            )
            print("before modifying client..")
            
            if modify_client=="modify" :
                client.id=client_id_mod
                print("the client is to be selected")
                client_to_del = OAuthClients.query.filter_by(id=client_id_mod).first()
                print("to be deleted")
                print("client is testing ---------------",client_to_del.name)
                print("client is testing ---------------",client_to_del.client_id)
                print("client is testing ---------------",client_to_del.client_secret)
                print("client is testing ---------------",client_to_del.authorize_url)
                print("client is testing ---------------",client_to_del.access_token_url)
                print("client is testing ---------------",client_to_del.api_base_url)
                print("client is testing ---------------",client_to_del.logout_url)
                print("the client is selected and is ",client_to_del)
                print(client_to_del)
                client.disconnect(oauth)
                db.session.delete(client_to_del)
                db.session.commit()
                db.session.flush()
            print("after modification")
            #adding new modified client
            print("----we are getting this client.name !!!!!!!!!!!!!!!!!1",client.name)
            db.session.add(client)
            db.session.commit()
            db.session.flush()
            
            print(client)
            client.register(oauth)
        return redirect(url_for('sso.sso_list'))

    @plugin_bp.route('/admin/sso/create', methods = ['GET', 'POST'])
    @admins_only
    def sso_create():
        if request.method == "POST":
            name = request.form["name"]
            modify_client =request.form["modify_client"]
            print("Am I ?",modify_client )
            client_id = request.form["client_id"]
            client_secret = request.form["client_secret"]
            access_token_url = request.form["access_token_url"]
            authorize_url = request.form["authorize_url"]
            api_base_url = request.form["api_base_url"]
            logout_url = request.form["logout_url"]
            post_logout_redirect_uri = request.form["post_logout_redirect_uri"]
            client = OAuthClients(
                name=name,
                client_id=client_id,
                client_secret=client_secret,
                access_token_url=access_token_url,
                authorize_url=authorize_url,
                api_base_url=api_base_url,
                logout_url=logout_url,
                post_logout_redirect_uri=post_logout_redirect_uri
            )
            
            #adding new client
            db.session.add(client)
            db.session.commit()
            db.session.flush()
            
            client.register(oauth)

            return redirect(url_for('sso.sso_list'))

        form = OAuthForm()
        return render_template('create.html', form=form, client="" )


    @plugin_bp.route("/sso/login/<int:client_id>", methods = ['GET'])
    def sso_oauth(client_id):
        '''
        client = oauth.create_client(client_id)
        #client= OAuthClients.query.filter_by(id=client_id).first()
        print("changed client creation redirection")
        print("client_id is",client_id )
        redirect_uri=url_for('sso.sso_redirect', client_id=client_id, _external=True)
        print(redirect_uri)
        print(client.authorize_redirect(redirect_uri))
        return client.authorize_redirect(redirect_uri)
        '''
        client= OAuthClients.query.filter_by(id=client_id).first()
        endpoint = client.authorize_url

        if get_config("user_mode") == "teams":
            scope = "profile team"
        else:
            scope = "profile"
	
	#client_id in database this is set in Keycloak
        client_id = client.client_id
        if client_id is None:
            error_for(
                endpoint="auth.login",
                message="OAuth Settings not configured. "
                "Ask your CTF administrator to configure Keycloak integration.",
            )
            return redirect(url_for("auth.login"))

        redirect_url = "{endpoint}?response_type=code&client_id={client_id}&scope={scope}&state={state}".format(endpoint=endpoint, client_id=client_id, scope=scope, state=session["nonce"])

        return redirect(redirect_url)

    @plugin_bp.route("/sso/redirect/<int:client_id>", methods = ['GET'])
    
    def sso_redirect(client_id):
    	#rate limit - @ratelimit(method="GET" , limit=10 ,interval=60)
        #fix token CSRF danger----------------------------------------------
        #------------------------------------------------------
        '''    
        print("client_id :",client_id)
        client = oauth.create_client(client_id)

        client_log = OAuthClients.query.filter_by(id=client_id).first()
        print(client_log.logout_url)
        
        #Set in order to be sent over to logout keycloak user
        set_config("current_keycloak_id",client.client_id)
        set_config("current_keycloak_secret",client.client_secret)
        set_config("current_keycloak_token",client.access_token_url)
        set_config("current_keycloak_logout",client_log.logout_url)
        set_config("current_post_logout_redirect_uri",client_log.post_logout_redirect_uri)

        print("client is testing ---------------",client.name)
        print("client is testing ---------------",client.client_id)
        print("client is testing ---------------",client.client_secret)
        print("client is testing ---------------",client.authorize_url)
        print("client is testing ---------------",client.access_token_url)
        print("client is testing ---------------",client.api_base_url)

        token=client.authorize_access_token()
        print("token here is client.authorize_access_token() ",token)
        api_data = client.get('',token=token).json()
        print("this is the api_data : ",api_data)
        user_name = api_data["preferred_username"]

        user_email = api_data["email"]
        user_roles = api_data.get("roles")

        user = Users.query.filter_by(email=user_email).first()
        if user is None:
            # Check if we are allowing registration before creating users
            if registration_visible() or get_app_config("OAUTH_ALWAYS_POSSIBLE") == True:
                user_type="user"
                user_hidden=False
                if 'administrator' in api_data.get('roles', []):
                    user_type="admin"
                    user_hidden=True

                user = Users(
                    name=user_name,
                    email=user_email,
                    type=user_type,
                    verified=True,
                    hidden=user_hidden
                )
                db.session.add(user)
                db.session.commit()
            else:
                log("logins", "[{date}] {ip} - Public registration via MLC blocked")
                error_for(
                    endpoint="auth.login",
                    message="Public registration is disabled. Please try again later.",
                )
                return redirect(url_for("auth.login")) 

        user.verified = True
        db.session.commit()

        if user_roles is not None and len(user_roles) > 0 and user_roles[0] in ["admin", "user"]:
            user_role = user_roles[0]
            if user_role != user.type:
                user.type = user_role
                db.session.commit()
                user = Users.query.filter_by(email=user_email).first()
                clear_user_session(user_id=user.id)

        login_user(user)
        set_config("keycloak_user_logged",True)
        print("no problem we logged in this user")
        return redirect(url_for("challenges.listing"))
    return plugin_bp
    '''
        print("client_id is coming from redirection ",client_id)
        client = OAuthClients.query.filter_by(id=client_id).first()
	
        oauth_code = request.args.get("code")
        print("oauth_code is : ",oauth_code)
        state = request.args.get("state")
        if session["nonce"] != state:
            log("logins", "[{date}] {ip} - OAuth State validation mismatch")
            error_for(endpoint="auth.login", message="OAuth State validation mismatch.")
            return redirect(url_for("auth.login"))
        
        #Set in order to be sent over to logout keycloak user
        set_config("current_keycloak_id",client.client_id)
        set_config("current_keycloak_secret",client.client_secret)
        set_config("current_keycloak_token",client.access_token_url)
        set_config("current_keycloak_logout",client.logout_url)
        set_config("current_post_logout_redirect_uri",client.post_logout_redirect_uri)
    
        if oauth_code:

            url = get_config("current_keycloak_token")

            client_secret = get_config("current_keycloak_secret")

            headers = {"content-type": "application/x-www-form-urlencoded"}
            client_id = get_config("current_keycloak_id")
            

            data = {
                "code": oauth_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code"
            }
            token_request = requests.post(url, data=data, headers=headers)
        
            if token_request.status_code == requests.codes.ok:

                #print("the whole token is :",token_request.json())
                token = token_request.json()["access_token"]
                user_url = client.api_base_url
                print("the url of api is ",user_url)
                headers = {
                    "Authorization": "Bearer " + str(token),
                    "Content-type": "application/json",
                }
                print("---------------------")
                        
                api_data = requests.get(url=user_url, headers=headers).json()

                #print("this is the api_data",api_data)
        
                user_id = api_data["sub"]
                user_name = api_data["preferred_username"]
                user_email = api_data["email"]
                user_type = "user"
                if 'administrator' in api_data.get('roles', []):
                    user_type="admin"

                user = Users.query.filter_by(email=user_email).first()
                if user is None:
                    # Respect the user count limit
                    num_users_limit = int(get_config("num_users", default=0))
                    num_users = Users.query.filter_by(banned=False, hidden=False).count()
                    if num_users_limit and num_users >= num_users_limit:
                        abort(
                            403,
                            description=f"Reached the maximum number of users ({num_users_limit}).",
                        )

                    # Check if we are allowing registration before creating users
                    if registration_visible() or mlc_registration():
                        user_hidden=False
                        if user_type=="admin":
                            user_hidden=True

                        user = Users(
                            name=user_name,
                            email=user_email,
                            oauth_id=user_id,
                            hidden=user_hidden,
                            type=user_type,        #default user is "user"
                            verified=True
                        )
                        db.session.add(user)
                        db.session.commit()
                    else:
                        log("logins", "[{date}] {ip} - Public registration via Keyboard blocked")
                        error_for(
                            endpoint="auth.login",
                            message="Public registration is disabled. Please try again later.",
                        )
                        return redirect(url_for("auth.login"))

                if get_config("user_mode") == TEAMS_MODE and user.team_id is None:
                    team_id = api_data["team"]["id"]
                    team_name = api_data["team"]["name"]

                    team = Teams.query.filter_by(oauth_id=team_id).first()
                    if team is None:
                        num_teams_limit = int(get_config("num_teams", default=0))
                        num_teams = Teams.query.filter_by(
                            banned=False, hidden=False
                        ).count()
                        if num_teams_limit and num_teams >= num_teams_limit:
                            abort(
                                403,
                                description=f"Reached the maximum number of teams ({num_teams_limit}). Please join an existing team.",
                            )

                        team = Teams(name=team_name, oauth_id=team_id, captain_id=user.id)
                        db.session.add(team)
                        db.session.commit()
                        clear_team_session(team_id=team.id)

                    team_size_limit = get_config("team_size", default=0)
                    if team_size_limit and len(team.members) >= team_size_limit:
                        plural = "" if team_size_limit == 1 else "s"
                        size_error = "Teams are limited to {limit} member{plural}.".format(
                            limit=team_size_limit, plural=plural
                        )
                        error_for(endpoint="auth.login", message=size_error)
                        return redirect(url_for("auth.login"))

                    team.members.append(user)
                    db.session.commit()

                if user.oauth_id is None:
                    user.oauth_id = user_id
                    user.verified = True
                    db.session.commit()
                    clear_user_session(user_id=user.id)

                login_user(user)
                set_config("keycloak_user_logged",True)
                #set_config("keycloak_login",True)
                return redirect(url_for("challenges.listing"))
            else:
                log("logins", "[{date}] {ip} - OAuth token retrieval failure")
                error_for(endpoint="auth.login", message="OAuth token retrieval failure.")
                ###
                return redirect(url_for("auth.login"))
        else:
            log("logins", "[{date}] {ip} - Received redirect without OAuth code")
            error_for(
                endpoint="auth.login", message="Received redirect without OAuth code."
            )
            return redirect(url_for("auth.login"))

    return plugin_bp
