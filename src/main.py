from flask import Flask, abort, jsonify, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

from wtforms import form, fields, validators
import flask_admin as admin
import flask_login as login
from flask_admin.contrib import sqla
from flask_admin import helpers, expose
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash

from Crypto.Cipher import AES

from linebot import (
    LineBotApi, WebhookHandler
)
from linebot.exceptions import (
    InvalidSignatureError
)
from linebot.models import (
    MessageEvent, TextMessage, TextSendMessage,
)
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ["FLASK_SECRET"]
db = SQLAlchemy(app)


AES_SECRET_KEY = os.environ["FLASK_AES_SECRET"]  # AES の共通鍵


YOUR_CHANNEL_ACCESS_TOKEN = os.environ["LINE_CHANNEL_ACCESS_TOKEN"]
YOUR_CHANNEL_SECRET = os.environ["LINE_CHANNEL_SECRET"]


line_bot_api = LineBotApi(YOUR_CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(YOUR_CHANNEL_SECRET)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_encrypted = db.Column(db.String(500), nullable=False)
    toban_date = db.Column(db.DateTime, nullable=False)
    tag = db.Column(db.String(500), nullable=False)
    nonce = db.Column(db.String(500), nullable=False)

    def __init__(self, name_encrypted, toban_date, tag, nonce):
        self.name_encrypted = name_encrypted
        self.toban_date = toban_date
        self.tag = tag
        self.nonce = nonce


class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(250))

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def __unicode__(self):
        return self.username


class LoginForm(form.Form):
    login = fields.StringField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('ユーザー名もしくはパスワードが違います。')

        if not check_password_hash(user.password, self.password.data):
            raise validators.ValidationError('ユーザー名もしくはパスワードが違います。')

    def get_user(self):
        return db.session.query(AdminUser).filter_by(login=self.login.data).first()


class RegistrationForm(form.Form):
    login = fields.StringField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        if db.session.query(AdminUser).filter_by(login=self.login.data).count() > 0:
            raise validators.ValidationError('同じユーザー名が存在します。')


def init_login():
    login_manager = login.LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(AdminUser).get(user_id)


class MyModelView(sqla.ModelView):
    def is_accessible(self):
        return login.current_user.is_authenticated


class MyAdminIndexView(admin.AdminIndexView):
    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            login.login_user(user)

        if login.current_user.is_authenticated:
            return redirect(url_for('.index'))
        link = '<p>アカウント未作成用 <a href="' + \
            url_for('.register_view') + '">ここをクリック</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = AdminUser()

            form.populate_obj(user)
            user.password = generate_password_hash(form.password.data)
            db.session.add(user)
            db.session.commit()
            login.login_user(user)
            return redirect(url_for('.index'))
        link = '<p>既にアカウントを持っている場合は <a href="' + \
            url_for('.login_view') + '">ここをクリックしてログイン</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        login.logout_user()
        return redirect(url_for('.index'))


init_login()
admin = admin.Admin(app, '管理者画面', index_view=MyAdminIndexView(),
                    base_template='my_master.html')
admin.add_view(MyModelView(AdminUser, db.session))
admin.add_view(MyModelView(Student, db.session))


def dec_data(cipher_data, tag, nonce):
    # 暗号化されたデータを復号
    cipher_dec = AES.new(AES_SECRET_KEY, AES.MODE_EAX, nonce)
    dec_data = cipher_dec.decrypt_and_verify(cipher_data, tag)
    return dec_data


@app.route("/add_student", methods=['POST'])
def add_student():
	request.data['name']

	"""
    name = request.data['name']
    cipher = AES.new(AES_SECRET_KEY.encode('utf-8'), AES.MODE_EAX)
    cipher_name, tag = cipher.encrypt_and_digest(name.encode('utf-8'))

    student_instance = Student(
        cipher_name.decode(), request.data["date"], tag.decode(
        ), cipher.nonce.decode()
    )
    db.session.add(student_instance)
    db.session.commit()
	"""


@app.route("/callback", methods=['POST'])
def callback():
    signature = request.headers['X-Line-Signature']
    body = request.get_data(as_text=True)
    app.logger.info("Request body: " + body)

    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)

    return 'OK'


@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    line_bot_api.reply_message(
        event.reply_token,
        TextSendMessage(text=event.message.text)
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
