from flask import Flask, jsonify, request
import json
import jwt
import datetime
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

from werkzeug.security import generate_password_hash, check_password_hash # https://www.youtube.com/watch?v=WxGBoY5iNXY
from sqlalchemy.sql import func  # https://stackoverflow.com/questions/13370317/sqlalchemy-default-datetime
from statistics import mean  # for weather stats
from statistics import median  # for weather stats
from statistics import mode, multimode  # for weather stats

# create an instance of the Flask class and assign to app
# __name__ refers to the default path of the package app = Flask(__name__)
app = Flask(__name__)
# triple / means file stored in same directory V
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///App.db'  # db path
app.config['SQLALCHEMY_ECHO'] = True  # echos SQL for debug
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # this needs to be true for auditing
app.config['SECRET_KEY'] = 'ItsPronouncedSeeHash2021'

db = SQLAlchemy(app)  # instanciate db object in sqlalchemy class with flask-app as argument
ma = Marshmallow(app)  # initialise marshmallow


# class definitions for sqlAlchey Object relational mapper
class Weather(db.Model):
    """Weather definition for SQLAlchemy"""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # coordinates = db.relationship("Coordinate", backref="Weather", uselist=False)
    longitude = db.Column(db.Float, nullable=False)  # coordinates (decmial)
    latitude = db.Column(db.Float, nullable=False)  # coordinates (decmial)
    hygrometer = db.Column(db.Float, nullable=False)  # hygrometer (0.0 -100)
    thermometer = db.Column(db.Float, nullable=False)  # thermometer (-200 - 200)
    udometer = db.Column(db.Integer, nullable=False)  # udometer (0-3000)
    anemometer = db.Column(db.Integer, nullable=False)  # anemometer (0-500)
    vane = db.Column(db.Integer, nullable=False)  # vane (0-360)
    date = db.Column(db.DateTime(timezone=True), default=func.now())  # this gets auto generated

    def __repr__(self):
        return '<Weather %r>' % self.id


class WeatherSchema(ma.SQLAlchemyAutoSchema):
    # definition used by serialization library based on user
    class Meta:
        # fields = ("id", "coordinates", "hygrometer", "thermometer", "udometer", "anemometer", "vane", "date")
        fields = ("id", "longitude", "latitude", "hygrometer", "thermometer", "udometer", "anemometer", "vane", "date")


weather_schema = WeatherSchema()
weathers_schema = WeatherSchema(many=True)


# class Coordinate(db.Model):
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     longitude = db.Column(db.Float, nullable=False)  # coordinates (decmial)
#     latitude = db.Column(db.Float, nullable=False)  # coordinates (decmial)
#     Weather_id = db.Column(db.Integer, db.ForeignKey("weather.id"), nullable=False)
#
#     def __repr__(self):
#         return '<Coordinate %r>' % self.id
#
#
# class CoordinateSchema(ma.SQLAlchemyAutoSchema):
#     # definition used by serialization library based on user
#     class Meta:
#         fields = ("id", "longitude", "latitude", "weather_id")
#
# coordinate_schema = CoordinateSchema()
# coordinates_schema = CoordinateSchema(many=True)

# class Temperature(db.Model):
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     date = db.Column(db.DateTime, nullable=False)
#
#     def __repr__(self):
#         return '<User %r>' % self.id


class User(db.Model):
    """User definition for SQLAlchemy"""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(40), nullable=False)
    access = db.Column(db.Boolean, default=0, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.id


class UserSchema(ma.SQLAlchemyAutoSchema):
    # definition used by serialization library based on user
    class Meta:
        fields = ("id", "username", "password", "access")


# instanciate objects based on marshmallow schema

user_schema = UserSchema()
users_schema = UserSchema(many=True)


@app.get("/")  # default endpoint
def hello_word():
    return "hello world!"

# ===============================================================================


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens'] # < this says non
        if not token:
            return jsonify({'Message': 'Missing valid token.'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data["username"]).first()

        except:
            return jsonify({'Message': 'Token is invalid'})

        return f(current_user.access, *args, **kwargs)

    return decorator


# ===============================================================================

@app.get("/Login")  # BASIC LOGIN
def login():
    auth = request.authorization
    if auth:
        if auth.username == "Francis" and auth.password == "APIPassword":
            return {"Message": "Authenticated"}
        else:
            return {"Message": "Username/Password incorrect"}, 401
    else:
        return {"Message": "No authorisation details"}, 401


@app.get("/Login2")  # LOGIN USER providing token
def login2():
    auth = request.authorization
    if auth:
        user = User.query.filter_by(username=auth.username).first()
        if user is None:
            return {"Message": "Username/Password incorrect"}, 401
        if check_password_hash(user.password, auth.password) and user.username == auth.username:
            token = jwt.encode({'username': auth.username, 'access': user.access,
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
                               , app.config['SECRET_KEY'])
            return {"Token": token}
        else:
            return {"Message": "Username/Password incorrect"}, 401
    else:
        return {"Message": "No authorisation details"}, 401


# ===============================================================================


@app.get("/users")  # GET USERS
@token_required
def users_get_with_token(access):
    result_users = User.query.all()
    return users_schema.jsonify(result_users)


@app.get("/users/count")  # GET USERS AMMOUNT
@token_required
def users_get_count(access):
    result_users = User.query.all()
    if (len(result_users) == 0):
        return {"Message": f"Table empty: {result_users}"}, 200
    else:
        return {"Message": f"Table count: {len(result_users)}"}, 200


@app.get('/users/<id>')  # GET USER VIA PATH
@token_required
def user_param_get(id, access):
    user = User.query.filter_by(id=id).first()
    if user is None:
        return {"Message": "Entity with id doesnt exist"}, 404
    return user_schema.jsonify(user)


@app.get('/users/get')  # GET USER VIA BODY
@token_required
def user_body_get(access):
    request_data = request.get_json()
    try:
        user = User.query.filter_by(id=request_data['id']).first()
        if user is None:
            return {"Message": "Entity with id doesnt exist"}, 404
        return user_schema.jsonify(user)
    except Exception:
        return {"Message": "ID not passed"}, 400


@app.get('/users/get-single-by-username')  # GET USER VIA BODY USERNAME PERAMETER
@token_required
def user_body_get_based_on(access):
    request_data = request.get_json()
    try:  # BLOCK WORKS IF MISSING USERNAME OR INVALID
        if request_data["username"] != "":  # CHECK TO SEE IF BLANK
            user = User.query.filter_by(username=request_data['username']).first()
            return user_schema.jsonify(user)
    except Exception:
        return {"Message": "Invalid username"}, 400


@app.get('/users/get-list-by-access')  # GET LIST USER VIA ACCESS BODY PERAMETER
@token_required
def users_body_get_based_on(access):
    request_data = request.get_json()
    try:  # TRY BLOCKS MISSING ACCESS VARIABLE
        raw_access = request_data['access']
        if raw_access.upper() == "TRUE" or raw_access.upper() == "T":  # NEEDEED BECAUSE READS BOOL AS STRING
            converted_access = True
        elif raw_access.upper() == "FALSE" or raw_access.upper() == "F":
            converted_access = False
        else:
            return {"Message": "Invalid access type (True/T or False/F)"}, 400

        result_users = User.query.filter_by(access=converted_access).all()
        return users_schema.jsonify(result_users)
    except Exception:
        return {"Message": "ID not passed"}, 400


# ===============================================================================


@app.post("/users/add")  # ADD USER - default makes regular user < change this to check if existing
@token_required
def user_add_json(access):
    request_data = request.get_json()
    try:
        if request_data["username"] != "" and len(request_data['password']) > 8:
            user = User.query.filter_by(username=request_data['username']).first()
            if user is None:
                try:
                    hashed_password = generate_password_hash(request_data["password"], method="sha256")
                    #  INSERT PASSWORD HASHING HERE
                    new_user = User(
                        username=request_data['username'],
                        password=hashed_password
                    )
                except Exception:
                    return {"Message": "Missing field/s"}, 400
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    return user_schema.jsonify(new_user)
                except Exception:
                    return {"Message": Exception},
            else:
                return {"Message": "Username is already taken"}, 501
        else:
            return {"Message": "Minimum requirements not met"}, 501
    except Exception:
        return {"Message": "Username/password invalid"}, 501


@app.post("/users/add-advanced")  # ADD USER - specify access < change this to check if existing
@token_required
def user_add_advanced_json(access):
    if access == False:
         return {"Message": "You are not permitted"}

    request_data = request.get_json()
    try:  # BLOCKS MISSING ACCESS OR USERNAME/PASSWORD
        raw_access = request_data['access']  # NEEDEED BECAUSE READS BOOL AS STRING
        if raw_access.upper() == "TRUE" or raw_access.upper() == "T":
            converted_access = True
        elif raw_access.upper() == "FALSE" or raw_access.upper() == "F":
            converted_access = False
        else:
            return {"Message": "Invalid access type (True/T or False/F)"}, 400

        if request_data["username"] != "" and len(request_data['password']) > 8:
            user = User.query.filter_by(username=request_data['username']).first()
            if user is None:
                try:
                    hashed_password = generate_password_hash(request_data["password"], method="sha256")
                    #  INSERT PASSWORD HASHING HERE
                    new_user = User(
                        username=request_data['username'],
                        password=hashed_password,
                        access=converted_access
                    )
                except Exception:
                    return {"Message": "Missing field/s"}, 501
            else:
                return {"Message": "Username is already taken"}, 400
        else:
            return {"Message": "Minimum requirements not met"}, 400
    except Exception:
        return {"Message": "Username/password invalid"}, 400
    try:
        db.session.add(new_user)
        db.session.commit()
        return user_schema.jsonify(new_user)
    except Exception:
        return {"Message": Exception}, 501


# ===============================================================================

@app.patch("/users/patch")
@token_required
def user_patch_json(access):
    if access == False:
        return {"Message": "You are not permitted"}
    json_data = request.get_json()
    return_statement = "Updated"
    user = User.query.filter_by(id=json_data['id']).first()
    if user is None:
        return {"Message": "Entity with id doesnt exist"}, 404
    else:
        try:
            if json_data['username'] != "":
                user.username = json_data['username']
                return_statement += " - Username"
        except:
            pass
        try:
            if len(json_data['password']) > 8:
                user.password = generate_password_hash(json_data["password"], method="sha256")
                return_statement += " - Password"
        except:
            pass
        try:
            if json_data['access'] != "":
                raw_access = json_data['access']  # NEEDEED BECAUSE READS BOOL AS STRING
                if raw_access.upper() == "TRUE" or raw_access.upper() == "T":
                    try:
                        user.access = True
                        return_statement += " - Access"

                    except:
                        return {"Message": "Submission error"}, 501
                elif raw_access.upper() == "FALSE" or raw_access.upper() == "F":
                    try:
                        user.access = False
                        return_statement += " - Access"
                    except:
                        return {"Message": "Submission error"}, 501
                else:
                    return {"Message": "Invalid access type (True/T or False/F)"}, 400
        except:
                pass
        db.session.commit()
        if return_statement != "Updated":
            return {"Message": f"Record {return_statement} Updated"}, 200
        else:
            return {"Message": "Missing field or minimum requirements"}, 400


@app.patch("/users/update-password")
@token_required
def user_update_password_json(access):
    json_data = request.get_json()
    try:
        current_user = User.query.filter_by(username=json_data["username"]).first()
        if current_user is None:
            return {"Message": "Entity with id doesnt exist"}, 404

        if check_password_hash(current_user.password, json_data["current_password"]):
            if len(json_data["update_password"]) > 8:
                try:
                    current_user.password = generate_password_hash(json_data["update_password"], method="sha256")
                    db.session.commit()
                    return {"Message": "Record updated in DB"}, 200
                except Exception:
                    return {"Message": Exception}, 501
            else:
                return {"Message": "Minimum requirements not met"}, 501
        else:
            return {"Message": "Current password incorrect"}, 501
    except Exception:
        return {"Message": "Error missing field"}, 400


@app.put("/users/update-advanced")  # MODIFY USER
@token_required
def user_update_json(access):
    if access == False:
        return {"Message": "You are not permitted"}
    json_data = request.get_json()
    try:
        if User.query.filter_by(id=json_data['id']).first() is None:
            return {"Message": "Entity with id doesnt exist"}, 404
    except Exception:
        return {"Message": "ID not passed"}, 404
    try:
        if json_data['username'] == "" and len(json_data['password']) > 8:
            return {"Message": "Invalid username/password"}, 501
        raw_access = json_data['access']
        if raw_access.upper() == "TRUE" or raw_access.upper() == "T":
            converted_access = True
        elif raw_access.upper() == "FALSE" or raw_access.upper() == "F":
            converted_access = False
        else:
            return {"Message": "Invalid access type (True/T or False/F)"}, 501
    except Exception:
        return {"Message": "Invalid fields or minimum requirements not met"}, 501
    try:
        if User.query.filter_by(username=json_data['username']).first() is None:

            User.query.filter_by(id=json_data['id']).update(  # < reads fields then wraps back to fail here
                dict(
                    username=json_data['username'],
                    password=json_data['password'],
                    access=converted_access
                )
            )
            db.session.commit()
            return {"Message": "Record updated"}, 200
        else:
            return {"Message": "Username already taken"}, 501
    except Exception:
        return {"Message": Exception}, 501


# ===============================================================================


@app.delete('/users/delete/<id>')  # DELETE USER
@token_required
def delete_one_user_route(id, access):
    if access == False:
        return {"Message": "You are not permitted"}
    if User.query.filter_by(id=id).first() is None:
        return {"Message": "Entity with id doesnt exist"}, 404
    try:
        User.query.filter_by(id=id).delete()
        db.session.commit()
        return {"Message": "Record deleted"}, 200
    except Exception:
        return {"Message": Exception}, 501


@app.delete('/users/delete-by-username')  ### DELETE BY JSON < make this
@token_required
def delete_one_user_by_username(access):
    if access == False:
        return {"Message": "You are not permitted"}
    json_data = request.get_json()
    if User.query.filter_by(username=json_data["username"]).first() is None:
        return {"Message": "Entity with username doesnt exist"}, 404
    try:
        User.query.filter_by(username=json_data["username"]).delete()
        db.session.commit()
        return {"Message": "Record deleted from DB"}, 200
    except Exception:
        return {"Message": "Entity with username doesnt exist"}, 404


# -------------------------------------------------------------------------------

@app.get("/weathers")  # GET WEATHER
@token_required
def weathers_get(access):
    result_weathers = Weather.query.all()
    return weathers_schema.jsonify(result_weathers)


@app.get('/weathers/<id>')  # GET USER VIA PATH
@token_required
def weather_param_get(id, access):
    weather = Weather.query.filter_by(id=id).first()
    if weather is None:
        return {"Message": "Entity with id doesnt exist"}, 404
    return weather_schema.jsonify(weather)


@app.get('/weathers/get')  # GET USER VIA BODY
@token_required
def weather_body_get(access):
    request_data = request.get_json()
    try:
        weather = Weather.query.filter_by(id=request_data['id']).first()
        if weather is None:
            return {"Message": "Entity with id doesnt exist"}, 404
        return weather_schema.jsonify(weather)
    except Exception:
        return {"Message": "ID not passed"}, 400


@app.get("/weathers/count")  # GET USERS AMMOUNT
@token_required
def weathers_get_count(access):
    result_weathers = Weather.query.all()
    if (len(result_weathers) == 0):
        return {"Message": f"Table empty: {result_weathers}"}, 200
    else:
        return {"Message": f"Table count: {len(result_weathers)}"}, 200


# https://stackoverflow.com/questions/4926757/sqlalchemy-query-where-a-column-contains-a-substring
@app.get('/weathers/get-by-day')  # GET WEATHERS BY DAY VIA BODY
@token_required
def weather_body_get_by_day(access):
    request_data = request.get_json()
    try:
        date = request_data["date"]
        weathers = Weather.query.filter(Weather.date.contains(date)).all()
        if len(weathers) == 0:
            return {"Message": "No entities were found"}, 404
        return weathers_schema.jsonify(weathers)
    except Exception:
        return {"Message": "Invalid date passed"}, 400


@app.get('/weathers/get-by-most-recent-and-location')  # GET WEATHERS BY DAY VIA BODY
@token_required
def weather_body_get_most_recent_by_location(access):
    request_data = request.get_json()
    try:
        weathers = Weather.query.filter(
            Weather.longitude.contains(request_data["longitude"]),
            Weather.latitude.contains(request_data["latitude"])
        ).all()
        if len(weathers) == 0:
            return {"Message": "No entities were found"}, 404
        return weather_schema.jsonify(weathers[-1])
    except Exception:
        return {"Message": "Invalid date passed"}, 400


@app.get('/weathers/get-by-day-temp-range')  # GET TEMP RANGE BY DAY VIA BODY
@token_required
def weather_body_get_day_range(access):
    request_data = request.get_json()
    try:
        date = request_data["date"]
        weathers = Weather.query.filter(Weather.date.contains(date)).order_by(Weather.thermometer).all()
        if len(weathers) == 0:
            return {"Message": "No entities were found"}, 404
        lowest = weathers[0].thermometer
        highest = weathers[-1].thermometer
        return {"Message": "Daily temperature range", "Lowest": lowest, "Highest": highest}, 200
    except Exception:
        return {"Message": "Invalid date passed"}, 400


@app.get('/weathers/get-by-day-stats')  # GET STATS BY DAY VIA BODY
@token_required
def weather_body_get_day_stats(access):
    request_data = request.get_json()
    try:
        date = request_data["date"]
        weathers = Weather.query.filter(Weather.date.contains(date)).all()
    except Exception:
        return {"Message": "Invalid date passed"}, 400
    if len(weathers) > 0:
        hygrometers = []
        thermometers = []
        udometers = []
        anemometers = []
        vanes = []
        try:
            for element in weathers:
                hygrometers.append(element.hygrometer)
                thermometers.append(element.thermometer)
                udometers.append(element.udometer)
                anemometers.append(element.anemometer)
                vanes.append(element.vane)
            return \
                {"aMessage": "Daily stats",
                 "Date": f"{date}",
                 "Hygrometers":
                     {"Collection": f"{hygrometers}", "Mean": f"{mean(hygrometers)}", "Median": f"{median(hygrometers)}"
                         , "Mode": f"{mode(hygrometers)}", "Multi-Mode": f"{multimode(hygrometers)}"},
                 "Thermometers":
                     {"Collection": f"{thermometers}", "Mean": f"{mean(thermometers)}",
                      "Median": f"{median(thermometers)}",
                      "Mode": f"{mode(thermometers)}", "Multi-Mode": f"{multimode(thermometers)}"},
                 "Udometers":
                     {"Collection": f"{udometers}", "Mean": f"{mean(udometers)}", "Median": f"{median(udometers)}",
                      "Mode": f"{mode(udometers)}", "Multi-Mode": f"{multimode(udometers)}"},
                 "Anemometers":
                     {"Collection": f"{anemometers}", "Mean": f"{mean(anemometers)}", "Median": f"{median(anemometers)}"
                         , "Mode": f"{mode(anemometers)}", "Multi-Mode": f"{multimode(anemometers)}"},
                 "Vanes":
                     {"Collection": f"{vanes}", "Mean": f"{mean(vanes)}", "Median": f"{median(vanes)}",
                      "Mode": f"{mode(vanes)}", "Multi-Mode": f"{multimode(vanes)}"},
                 }
        except:
            return {"Message": "No entries found with Date"}, 404
            return {"Message": "Calculation error"}, 400
    else:
        return{"Message": "No entries found with Date"}, 404


    # V tried these to avoid for loop and long lists but doesnt work
    # thermometers = weathers.with_only_columns(Weather.thermometer)
    # thermometers = weathers.query(Weather.thermometer).all()
    # thermometers = weathers.query(Weather.thermometer).with_columns.all()


# ===============================================================================


@app.post("/weathers/add")  # ADD WEATHER
@token_required
def weather_add_json(access):
    request_data = request.get_json()
    try:
        x = float(request_data["longitude"])
        y = float(request_data["latitude"])
        if float(request_data["hygrometer"]) < float(0) or float(request_data["hygrometer"]) > float(100):
            return {"Message": "hygrometer out of range (0.0 - 100)"}, 400

        if float(request_data["thermometer"]) < float(-200) or float(request_data["thermometer"]) > float(200):
            return {"Message": "thermometer out of range (-200 - 200)"}, 400

        if int(request_data["udometer"]) < int(0) or int(request_data["udometer"]) > int(3000):
            return {"Message": "udometer out of range (0 - 3000)"}, 400

        if float(request_data["anemometer"]) < float(0) or float(request_data["anemometer"]) > float(500):
            return {"Message": "anemometer out of range (0.0 - 500)"}, 400

        if int(request_data["vane"]) < int(0) or int(request_data["vane"]) > int(360):
            return {"Message": "vane out of range (0 - 360)"}, 400
    except Exception:
        return {
            "AMessage": "Data incorrect format, presented as below:",
            "hygrometer": "0.0 - 100.0", "thermometer": "-200.0 - 200.0",
            "udometer": "0 - 3000", "anemometer": "0.0 - 500", "vane": "0 - 360",
            "Longitude": "-1520.0022 - 1520.0022", "Latitude": "-1520.0022 - 1520.0022"
        }, 400
    new_weather = Weather(
        longitude=request_data['longitude'], latitude=request_data['latitude'],
        hygrometer=request_data['hygrometer'], thermometer=request_data['thermometer'],
        udometer=request_data['udometer'], anemometer=request_data['anemometer'], vane=request_data['vane']
    )

    try:
        db.session.add(new_weather)
        db.session.commit()
        print("Record added to DB"), 200
        print(json.dumps(request_data, indent=4))
    except Exception:
        return {"Message": "Error on submission"}, 501

    return weather_schema.jsonify(new_weather)


# ===============================================================================


@app.patch("/weathers/patch")
@token_required
def weather_patch_json(access):
    if access == False:
        return {"Message": "You are not permitted"}
    json_data = request.get_json()
    return_statement = "Updated"
    weather = Weather.query.filter_by(id=json_data['id']).first()
    if weather is None:
        return {"Message": "Entity with id doesnt exist"}, 404
    else:
        try:
            x = float(json_data["longitude"])
            if json_data['longitude'] != "":
                weather.longitude = json_data['longitude']
                return_statement += " - Longitude"
        except:
            pass
        try:
            x = float(json_data["latitude"])
            if json_data['latitude'] != "":
                weather.latitude = json_data['latitude']
                return_statement += " - latitude"
        except:
            pass
        try:
            if float(json_data["hygrometer"]) < float(0) or float(json_data["hygrometer"]) > float(100):
                return {"Message": "hygrometer out of range (0.0 - 100)"}, 501
            else:
                weather.latitude = json_data['hygrometer']
                return_statement += " - hygrometer"
        except:
            pass

        try:
            if float(json_data["thermometer"]) < float(-200) or float(json_data["thermometer"]) > float(200):
                return {"Message": "thermometer out of range (-200 - 200)"}, 501
            else:
                weather.thermometer = json_data['thermometer']
                return_statement += " - thermometer"
        except:
            pass
        try:
            if int(json_data["udometer"]) < int(0) or int(json_data["udometer"]) > int(3000):
                return {"Message": "udometer out of range (0 - 3000)"}, 501
            else:
                weather.udometer = json_data['udometer']
                return_statement += " - udometer"
        except:
            pass
        try:
            if float(json_data["anemometer"]) < float(0) or float(json_data["anemometer"]) > float(500):
                return {"Message": "anemometer out of range (0.0 - 500)"}, 501
            else:
                weather.anemometer = json_data['anemometer']
                return_statement += " - anemometer"
        except:
            pass
        try:
            if int(json_data["vane"]) < int(0) or int(json_data["vane"]) > int(360):
                return {"Message": "vane out of range (0 - 360)"}, 501
            else:
                weather.vane = json_data['vane']
                return_statement += " - vane"
        except:
            pass

        db.session.commit()
        if return_statement != "Updated":
            return {"Message": f"Record {return_statement} Updated"}, 200
        else:
            return {
                       "AMessage": "Data incorrect format or non-minimum requirements, presented as below:",
                       "hygrometer": "0.0 - 100.0", "thermometer": "-200.0 - 200.0",
                       "udometer": "0 - 3000", "anemometer": "0.0 - 500", "vane": "0 - 360",
                       "Longitude": "-1520.0022 - 1520.0022", "Latitude": "-1520.0022 - 1520.0022"
                   }, 400


@app.put("/weathers/update")  # MODIFY WEATHER
@token_required
def weather_update_json(access):
    if access == False:
        return {"Message": "You are not permitted"}
    json_data = request.get_json()
    # V error checking to see if entry passed exists (includes non integer or no entry passed)
    weather = Weather.query.filter_by(id=json_data['id']).first()
    if weather is None:
        return {"Message": "Entity with id doesnt exist"}, 404

    try:
        x = float(json_data["longitude"])
        y = float(json_data["latitude"])
        if float(json_data["hygrometer"]) < float(0) or float(json_data["hygrometer"]) > float(100):
            return {"Message": "hygrometer out of range (0.0 - 100)"}, 501

        if float(json_data["thermometer"]) < float(-200) or float(json_data["thermometer"]) > float(200):
            return {"Message": "thermometer out of range (-200 - 200)"}, 501

        if int(json_data["udometer"]) < int(0) or int(json_data["udometer"]) > int(3000):
            return {"Message": "udometer out of range (0 - 3000)"}, 501

        if float(json_data["anemometer"]) < float(0) or float(json_data["anemometer"]) > float(500):
            return {"Message": "anemometer out of range (0.0 - 500)"}, 501

        if int(json_data["vane"]) < int(0) or int(json_data["vane"]) > int(360):
            return {"Message": "vane out of range (0 - 360)"}, 501
    except Exception:
        return {
            "AMessage": "Data incorrect format, presented as below:",
            "hygrometer": "0.0 - 100.0", "thermometer": "-200.0 - 200.0",
            "udometer": "0 - 3000", "anemometer": "0.0 - 500", "vane": "0 - 360",
            "Longitude": "-1520.0022 - 1520.0022", "Latitude": "-1520.0022 - 1520.0022"
        }, 400
    try:
        Weather.query.filter_by(id=json_data['id']).update(
            dict(
                longitude=json_data['longitude'],
                latitude=json_data['latitude'],
                hygrometer=json_data['hygrometer'],
                thermometer=json_data['thermometer'],
                udometer=json_data['udometer'],
                anemometer=json_data['anemometer'],
                vane=json_data['vane']
            )
        )
        db.session.commit()
        return {"Message": "Record updated in DB"}, 200
    except Exception:
        return {"Message": "Error on update"}, 501


# @app.put("/weathers/update-date")  # MODIFY DATE - doesnt work not sure the format for input
# @token_required
# def weather_update_date_json(access):
#     if access == False:
#         return {"Message": "You are not permitted"}
#     json_data = request.get_json()
#     weather = Weather.query.filter_by(id=json_data['id']).first()
#     if weather is None:
#         return {"Message": "Entity with id doesnt exist"}
#     try:
#         raw_date = json_data["date"]
#
#         Weather.query.filter_by(id=json_data['id']).update(
#             dict(
#                 date=json_data['date']
#             )
#         )
#         db.session.commit()
#     except Exception:
#         return {"Message": "Error fulfilling update request"}
#     return {"Message": "Record updated in DB"}


# ===============================================================================

@app.delete('/weathers/delete/<id>')  # DELETE WEATHER
@token_required
def delete_one_weather_route(id, access):
    if access == False:
        return {"Message": "You are not permitted"}
    if Weather.query.filter_by(id=id).first() is None:
        return {"Message": "Entity with id doesnt exist"}, 404
    try:
        Weather.query.filter_by(id=id).delete()
        db.session.commit()
        return {"Message": "Record deleted"}, 200
    except Exception:
        return {"Message": Exception}, 400