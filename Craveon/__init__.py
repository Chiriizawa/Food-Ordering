from flask import Flask, session, redirect, url_for, flash
from Craveon.customer.customer import customer
from Craveon.admin.admin import admin

def create_app():
    app = Flask(__name__)

    app.secret_key = 'ray' 

    app.register_blueprint(customer, url_prefix='/CraveOn')
    app.register_blueprint(admin, url_prefix='/Admin')

    return app