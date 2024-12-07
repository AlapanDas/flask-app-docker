from flask import Flask, jsonify,request
from dotenv import load_dotenv
import os
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, null
import bcrypt

import datetime

from service import hashpassword
from tokenService import generate_access_token, generate_refresh_token,validate_token,renew_access_token

load_dotenv()


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres.ygnicpmynrjjfwxzytgq:{0}@aws-0-us-west-1.pooler.supabase.com:6543/postgres'.format(os.getenv('PASSWORD'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
db = SQLAlchemy(app)

class Users(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.Text, primary_key=True)
    password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now, nullable=True)
    isadmin = db.Column('isAdmin', db.Boolean, nullable=True)
    linked_account = db.Column(db.Integer, db.ForeignKey('account.acc_no'), nullable=True)
    emailid = db.Column(db.Text, unique=True, nullable=True)

    # Relationships
    linked_account_rel = db.relationship('Account', backref='users', foreign_keys=[linked_account])
    def to_dict(self):
        return {
            "username": self.username,
            "isadmin": self.isadmin,
            "emailid": self.emailid,
            "linked_account": self.linked_account,
        }

class Customer(db.Model):
    __tablename__ = 'customer'

    acc_no = db.Column(db.Integer, db.ForeignKey('account.acc_no'), primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    contact_number = db.Column(db.Numeric, nullable=True)  # Use Numeric for decimal values

    # Relationships
    account = db.relationship('Account', backref='customer', foreign_keys=[acc_no])

class Branch(db.Model):
    __tablename__ = 'branch'

    branch_id = db.Column(db.Integer, primary_key=True)
    b_name = db.Column(db.String(255), nullable=True)
    addr = db.Column(db.String(255), nullable=True)

class Login(db.Model):
    __tablename__ = 'login'

    username = db.Column(db.Text, db.ForeignKey('users.username'), primary_key=True) 
    exp = db.Column(db.DateTime)
    iat = db.Column(db.DateTime)

    # Relationships
    username_rel = db.relationship('Users', backref='login', foreign_keys=[username])

class Account(db.Model):
    __tablename__ = 'account'

    acc_no = db.Column(db.Integer, primary_key=True)
    acc_type = db.Column(db.String(20), nullable=True)
    balance = db.Column(db.Integer, nullable=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.branch_id'), nullable=True)
    roi = db.Column(db.Integer, nullable=True)
    open_data = db.Column(db.Date, nullable=True)

    # Relationships
    branch = db.relationship('Branch', backref='accounts', foreign_keys=[branch_id])


@app.route("/")
@cross_origin()
def seeAll():
    users=Users.query.all()
    return {
        "users": [
            {
                "username": user.username,
                "emailid": user.emailid,
                "created_at": user.created_at,
                "isadmin": user.isadmin
            }
            for user in users
        ]
    }

@app.route('/user/login',methods=['POST'])
@cross_origin()
def login():
    data=request.get_json()
    username = data.get('username')
    password = hashpassword(data.get('password'))
    try:
        user=Users.query.filter(and_(Users.username == username,
        Users.password == password )).first();

        access_token = generate_access_token(user.to_dict())
        refresh_token = generate_refresh_token(user.to_dict())
        if user:
            return jsonify({
                "message": "User validated successfully",
                "auth": {
                "accessToken":access_token,
                "refreshToken": refresh_token,
                }
            })
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except:
        return jsonify({'error':"Invalid username or password"}),404



@app.route('/user/signin',methods=['POST'])
@cross_origin()
def signin():
    data = request.get_json()  

    # Extract data fields
    username = data.get('username')
    password = hashpassword(data.get('password'))
    emailid = data.get('emailid')
    isadmin = data.get('isadmin', False)
    linked_account = data.get('linked_account')  

    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

  
    if Users.query.filter_by(username=username).first():
        return jsonify({"error": "User with this username already exists"}), 409

    
    new_user = Users(
        username=username,
        password=password,
        emailid=emailid,
        isadmin=isadmin,
        linked_account=linked_account,
        created_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

   
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "User added successfully",
        "user": {
            "username": new_user.username,
            "emailid": new_user.emailid,
            "isadmin": new_user.isadmin,
            "linked_account": new_user.linked_account
        }
    }), 201


# if __name__ == "__main__":
#   #    app = create_app()
#   print(" Starting app...")
#   app.run(host="0.0.0.0", port=5050)

@app.route('/user/revalidate',methods=['GET'])
@cross_origin()
def refresh():
    data=request.headers

    refreshToken=data.get('Authorization').split()[1]
    try:
        payload=(validate_token(refreshToken))
        now=datetime.datetime.now()
        try:
            user=Login.query.filter_by(username=payload['username']).first()
            if user:
                user.iat=now
                user.exp=now + datetime.timedelta(days=1)
                access_token = renew_access_token(refreshToken)
                try:
                    db.session.commit()
                    print(f"Updated login record for username successfully.")
                    return jsonify({
                    "message": "User revalidated successfully",
                    "auth": {
                    "accessToken":access_token,
                    "refreshToken": refreshToken,
                    }
                    }),200
                except Exception as e:
                    db.session.rollback() 
                    print(f"Failed to update login record: {e}")
        except:
            db.session.rollback()
            raise NameError
    except Exception as e:
        print(e)
        return jsonify({"message":"Token has expired"}),401


if __name__ == "__main__":
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app.
    app.run(host="127.0.0.1", port=8080, debug=True)