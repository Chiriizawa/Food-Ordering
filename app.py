from flask import Flask, session, redirect, url_for, flash
from flask_mail import Mail
from flask_cors import CORS
from Craveon.__init__ import create_app

mail = Mail()

app = create_app()

# Allow CORS for all origins (all ports)
CORS(app, supports_credentials=True)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'craveon129@gmail.com'
app.config['MAIL_PASSWORD'] = 'eorsaacreayfwlnw' 
app.config['MAIL_DEFAULT_SENDER'] = 'craveon129@gmail.com'

mail.init_app(app)

if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5000, debug=True)
