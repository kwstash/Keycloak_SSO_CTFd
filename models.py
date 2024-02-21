from CTFd.models import db


class OAuthClients(db.Model):
    __tablename__ = "oauth_clients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    client_id = db.Column(db.Text)
    client_secret = db.Column(db.Text)
    access_token_url = db.Column(db.Text)
    authorize_url = db.Column(db.Text)
    api_base_url = db.Column(db.Text)
    logout_url = db.Column(db.Text)
    print("Entering database to add logout_url")
    # In a later update you will be able to customize the login button
    color = db.Column(db.Text)
    icon = db.Column(db.Text)
    post_logout_redirect_uri =db.Column(db.Text)

    def register(self, oauth):
        oauth.register(
            name=self.id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            access_token_url=self.access_token_url,
            authorize_url=self.authorize_url,
            api_base_url=self.api_base_url,
            logout_url=self.logout_url,
            post_logout_redirect_uri=self.post_logout_redirect_uri,
            client_kwargs={'scope': 'profile roles'}
        )

    def disconnect(self, oauth):
        oauth._registry[self.id] = None
        oauth._clients[self.id] = None
