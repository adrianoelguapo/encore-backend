from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_cors import CORS
from bson import ObjectId
from datetime import datetime, timedelta, UTC
from functools import wraps
import os
from werkzeug.utils import secure_filename

# --- Importar librerías para JWT y BCRYPT ---
import jwt
from flask_bcrypt import Bcrypt

# --- Iniciar el programa ---
app = Flask(__name__)

# --- Configuración de subida de archivos ---
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Crear directorio si no existe (asegurarse) ---
os.makedirs(UPLOAD_FOLDER, exist_ok = True)

# --- CORS para permitir peticiones desde el front ---
CORS(app)

# --- Configuración de Mongo ---
app.config["MONGO_URI"] = "mongodb+srv://admin:123@cluster0.tz018.mongodb.net/encore?retryWrites=true&w=majority"
mongo = PyMongo(app)
db = mongo.db

# --- Instancia de bcrypt para hashear las pass ---
bcrypt = Bcrypt(app)

# --- Clave para JWT ---
# --- Para corrección fácil se mete la clave a pelo (no tener en cuenta sé que hay que ponerla en el .env) ---
app.config["SECRET_KEY"] = "W5ypf3Rc6essPEUbml69lG1Q4O9tl2ZDJSysu9fSx7Y"

# --- Métodos auxiliares ---

# --- Generar ID para crear nuevos usuarios o actividades sin que se repitan (pilla el máximo y suma 1) ---
def get_next_id(collection_name):

    collection = db[collection_name]
    last_doc = collection.find_one(sort = [("id", -1)])
    return 1 if not last_doc else last_doc["id"] + 1

# --- Restringir extensiones para subir imágenes ---
def allowed_file(filename):
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Recuperar inicio y fin de una actividad (para evitar duplicar datos en las reservas) ---
def get_activity_dates(activity_id):

    activity = db.activities.find_one({"id": activity_id})

    if not activity:

        return None, None

    return activity["start"], activity["finish"]

# --- Formatear fecha para el frontend (siempre UTC con Z) ---
def format_date_utc(dt):

    if not dt or not isinstance(dt, datetime):

        return dt
    
    # --- Si es naive (sin zona horaria), asumimos que es UTC y le añadimos Z ---
    if dt.tzinfo is None:

        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # --- Si es aware, la convertimos a UTC y usamos el formato con Z ---
    return dt.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')

# --- Comprobar si alguna reserva pisa el horario de otra (solo se tienen en cuenta las reservas no canceladas) ---
def check_time_overlap(user_bookings, new_start, new_finish, exclude_activity_id = None, activities_map = None):

    # --- if activities_map is not provided, fetch all activities once (fallback) ---
    if activities_map is None:
        activities = list(db.activities.find({}, {"_id": 0}))
        activities_map = {a["id"]: a for a in activities}

    # --- Se recorren todas las reservas del usuario ---
    for booking in user_bookings:

        # --- Excluir la actividad específica si se indica ---
        if exclude_activity_id and booking["activity_id"] == exclude_activity_id:

            continue
        
        # --- Solo comprobar reservas activas (no canceladas) ---
        if booking.get("activity_state") in ["cancel", "no assist"]:

            continue
        
        # --- Obtener las fechas de la actividad de la reserva desde el mapa ---
        activity = activities_map.get(booking["activity_id"])
        
        # --- Si no se encuentra la actividad, saltar ---
        if not activity:

            continue
            
        booking_start = activity["start"]
        booking_finish = activity["finish"]
        
        # --- Comprobar si se pisan: dos periodos se pisan si uno empieza antes de que termine el otro ---
        if (new_start < booking_finish and new_finish > booking_start):
            
            return True
    
    return False


# --- Métodos de autenticación ---

# --- Método para proteger endpoints que requieren autenticación (cualquier usuario que no haya iniciado sesión no podrá acceder) ---
def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        # --- Iniciar variable para guardar el token ---
        token = None
        
        # --- El token se envía en el header Auth ---
        if 'Auth' in request.headers:

            auth_header = request.headers['Auth']

            try:

                # --- Se divide el header en dos partes y se pilla la segunda (el token) ---
                token = auth_header.split(" ")[1]

            # --- Si no se puede dividir el header devuelve error ---
            except IndexError:

                return jsonify({"error": "Formato de token inválido"}), 401
        
        # --- Si no se envía el token devuelve error ---
        if not token:

            return jsonify({"error": "Token no proporcionado"}), 401
        
        try:
            
            # --- Decodificar el token ---
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms = ["HS256"])
            
            # --- Obtener el usuario de la base de datos ---
            current_user = db.users.find_one({"id": data["user_id"]}, {"_id": 0, "password": 0})
            
            # --- Si no se encuentra el usuario devuelve error ---
            if not current_user:

                return jsonify({"error": "Usuario no encontrado"}), 401
        
        # --- Si el token ha expirado devuelve error ---
        except jwt.ExpiredSignatureError:

            return jsonify({"error": "Token expirado"}), 401

        # --- Si el token es inválido devuelve error ---
        except jwt.InvalidTokenError:

            return jsonify({"error": "Token inválido"}), 401
        
        # --- Pasar el usuario actual a la función ---
        return f(current_user, *args, **kwargs)
    
    return decorated

# --- Método para proteger los endpoints del admin ---
def admin_required(f):

    @wraps(f)
    def decorated(current_user, *args, **kwargs):

        # --- Si el usuario no es admin devuelve error ---
        if current_user.get("role") != "admin":

            return jsonify({"error": "Acceso denegado. Se requiere rol de administrador"}), 403
        
        # --- Pasar el usuario actual a la función ---
        return f(current_user, *args, **kwargs)
    
    return decorated


# --- ENDPOINTS ---

# --- POST /api/auth/login -> Iniciar sesión ---
@app.route('/api/auth/login', methods = ['POST'])
def login():

    try:

        # --- Se obtienen nombre y contraseña de la petición ---
        data = request.json
        username = data.get("username")
        password = data.get("password")
        
        # --- Validar que se proporcionen nombre de usuario y pass ---
        if not username or not password:

            return jsonify({"error": "Username y password son requeridos"}), 400
        
        # --- Busca el usuario en base de datos (se busca por username porque es UNIQUE) ---
        user = db.users.find_one({"username": username})
        
        # --- Verificar que el usuario existe y la contraseña es correcta ---
        if not user or not bcrypt.check_password_hash(user["password"], password):

            return jsonify({"error": "Credenciales inválidas"}), 401
        
        # --- Generar token válido por 24 horas ---
        token = jwt.encode({

            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "exp": datetime.now(UTC) + timedelta(hours = 24)

        }, app.config["SECRET_KEY"], algorithm = "HS256")
        
        # --- Guardar datos del usuario (sin contraseña, ya que no se necesita porque ya está el token) ---
        user_data = {

            "id": user["id"],
            "username": user["username"],
            "name": user["name"],
            "role": user["role"]

        }
        
        # --- Se devuelve el token y los datos del usuario ---
        return jsonify({

            "message": "Login exitoso",
            "token": token,
            "user": user_data

        }), 200
        
    # --- Si hay algún error, se devuelve un error ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- POST /api/auth/register -> Registrar nuevo usuario ---
@app.route('/api/auth/register', methods = ['POST'])
def register():

    try:

        # --- Se obtienen los datos de la petición ---
        data = request.json
        username = data.get("username")
        password = data.get("password")
        name = data.get("name")
        role = data.get("role", "user") # --- Se asigna rol de usuario por defecto ---
        
        # --- Validar que se proporcionen nombre, username y pass ---
        if not username or not password or not name:

            return jsonify({"error": "All fields are required"}), 400
        
        # --- Verificar que el nombre de usuario a registrar no esté ocupado ---
        existing_user = db.users.find_one({"username": username})

        # --- Si el nombre de usuario ya está ocupado devuelve error ---
        if existing_user:

            return jsonify({"error": "Username already taken"}), 409
        
        # --- Hashear la pass con bcrypt ---
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # --- Se crea el nuevo usuario ---
        new_user = {

            "id": get_next_id("users"),
            "username": username,
            "password": hashed_password,
            "name": name,
            "role": role,
            "bookings": []

        }
        
        # --- Se inserta el nuevo usuario en la base de datos ---
        db.users.insert_one(new_user)
        
        # --- Se genera el token JWT para el nuevo usuario ---
        token = jwt.encode({

            "user_id": new_user["id"],
            "username": new_user["username"],
            "role": new_user["role"],
            "exp": datetime.now(UTC) + timedelta(hours = 24)

        }, app.config["SECRET_KEY"], algorithm = "HS256")
        
        # --- Se preparan los datos del usuario (sin pass (ya existe el token) ni el id de Mongo (no se utiliza)) ---
        user_data = {

            "id": new_user["id"],
            "username": new_user["username"],
            "name": new_user["name"],
            "role": new_user["role"]

        }
        
        # --- Se devuelve el token y los datos del usuario ---
        return jsonify({

            "message": "Register was successful",
            "token": token,
            "user": user_data

        }), 201
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- GET /api/users -> Obtener todos los usuarios (requiere admin) ---
@app.route('/api/users', methods = ['GET'])
@token_required
@admin_required
def get_all_users(current_user):

    try:

        # --- Se obtienen todos los usuarios (sin pass ni id de Mongo) ---
        users = list(db.users.find({}, {"_id": 0, "password": 0}))
        
        # --- Se devuelve la lista de usuarios ---
        return jsonify(users), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- GET /api/users/<int:id_usuario> -> Obtener un usuario en concreto ---
@app.route('/api/users/<int:id_usuario>', methods = ['GET'])
@token_required
def get_user(current_user, id_usuario):

    try:

        # --- Verificar permisos: solo puede ver su propio perfil y los admin pueden ver cualquier usuario ---
        if current_user["id"] != id_usuario and current_user["role"] != "admin":

            return jsonify({"error": "No tienes permisos para ver este usuario"}), 403
        
        # --- Se busca el usuario por ID (sin pass ni id de Mongo) ---
        user = db.users.find_one({"id": id_usuario}, {"_id": 0, "password": 0})
        
        # --- Si no se encuentra el usuario, se devuelve error ---
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        # --- Se devuelve el usuario ---
        return jsonify(user), 200
        
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- PUT /api/users/<int:id_usuario> -> Modificar un usuario en concreto ---
@app.route('/api/users/<int:id_usuario>', methods = ['PUT'])
@token_required
def modify_user(current_user, id_usuario):

    try:

        # --- Verificar permisos: solo puede modificar su propio perfil y los admin pueden modificar cualquier usuario ---
        if current_user["id"] != id_usuario and current_user["role"] != "admin":

            return jsonify({"error": "No tienes permisos para modificar este usuario"}), 403
        
        # --- Se obtienen los datos de la petición ---
        data = request.json
        name = data.get("name")
        username = data.get("username")
        password = data.get("password")
        
        # --- Validar que se envíen todos los campos requeridos ---
        if not name or not username or not password:

            return jsonify({"error": "Name, username y password son requeridos"}), 400
        
        # --- Buscar el usuario a modificar ---
        user = db.users.find_one({"id": id_usuario})
        
        # --- Si no se encuentra el usuario, se devuelve error ---
        if not user:

            return jsonify({"error": "Usuario no encontrado"}), 404
        
        # --- Verificar que el nuevo nombre de usuario no esté ocupado ---
        existing_user = db.users.find_one({

            "username": username,
            "id": {"$ne": id_usuario}  # --- No se cuenta al usuario actual ---

        })
        
        # --- Si el nombre de usuario ya existe, devolver error ---
        if existing_user:

            return jsonify({"error": "El username ya existe"}), 409
        
        # --- Hashear la nueva contraseña ---
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # --- Preparar campos a actualizar ---
        update_fields = {

            "name": name,
            "username": username,
            "password": hashed_password

        }
        
        # --- Actualizar el usuario en la base de datos ---
        db.users.update_one({"id": id_usuario}, {"$set": update_fields})
        
        # --- Guardar usuario actualizado (sin pass ni id de Mongo) ---
        updated_user = db.users.find_one({"id": id_usuario}, {"_id": 0, "password": 0})
        
        # --- Devolver usuario actualizado ---
        return jsonify({

            "message": "Usuario actualizado exitosamente",
            "user": updated_user

        }), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- DELETE /api/users/<int:id_usuario> -> Eliminar un usuario en concreto ---
@app.route('/api/users/<int:id_usuario>', methods = ['DELETE'])
@token_required
@admin_required
def delete_user(current_user, id_usuario):

    try:

        # --- Buscar el usuario a eliminar ---
        user = db.users.find_one({"id": id_usuario})
        
        # --- Si no se encuentra el usuario, devolver error ---
        if not user:

            return jsonify({"error": "Usuario no encontrado"}), 404
        
        # --- Eliminar el usuario de todas las actividades donde esté registrado ---
        db.activities.update_many(

            {"users": user["username"]},
            {"$pull": {"users": user["username"]}}

        )
        
        # --- Eliminar el usuario de la base de datos ---
        db.users.delete_one({"id": id_usuario})
        
        # --- Devolver mensaje de éxito ---
        return jsonify({"message": "Usuario eliminado exitosamente"}), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- GET /api/users/<int:id_usuario>/bookings -> Obtener las reservas de un usuario en concreto ---
@app.route('/api/users/<int:id_usuario>/bookings', methods = ['GET'])
@token_required
def get_user_bookings(current_user, id_usuario):

    try:

        # --- Verificar permisos: solo puede ver sus propias reservas y los admin pueden ver las reservas de cualquier usuario ---
        if current_user["id"] != id_usuario and current_user["role"] != "admin":

            return jsonify({"error": "No tienes permisos para ver estas reservas"}), 403
        
        # --- Buscar el usuario ---
        user = db.users.find_one({"id": id_usuario})
        
        # --- Si no se encuentra el usuario, devolver error ---
        if not user:

            return jsonify({"error": "Usuario no encontrado"}), 404
        
        # --- Buscar todas las actividades para evitar N+1 queries ---
        activities_list = list(db.activities.find({}, {"_id": 0}))
        activities_map = {a["id"]: a for a in activities_list}

        # --- Añadir información de las actividades a las reservas ---
        enriched_bookings = []

        # --- Recorrer las reservas del usuario ---
        for booking in user.get("bookings", []):
            
            # --- Buscar la actividad en el mapa ---
            activity = activities_map.get(booking["activity_id"])
            
            # --- Si se encuentra la actividad, se añade a la lista ---
            if activity:
                enriched_bookings.append({
                    "activity_id": booking["activity_id"],
                    "activity_name": activity["name"],
                    "activity_description": activity["description"],
                    "activity_start": format_date_utc(activity.get("start")),
                    "activity_finish": format_date_utc(activity.get("finish")),
                    "activity_state": booking["activity_state"],
                    "booked_at": format_date_utc(booking.get("booked_at"))
                })
        
        # --- Devolver las reservas ---    
        return jsonify(enriched_bookings), 200
        
    # --- Si hay algún error, se devuelve ---
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# --- POST /api/users/<int:id_usuario>/bookings/<int:id_actividad> -> Reservar una actividad ---
@app.route('/api/users/<int:id_usuario>/bookings/<int:id_actividad>', methods = ['POST'])
@token_required
def book_activity(current_user, id_usuario, id_actividad):

    try:
        # --- Verificar permisos: solo puede reservar para si mismo y los admin pueden reservar para cualquier usuario ---
        if current_user["id"] != id_usuario and current_user["role"] != "admin":
            return jsonify({"error": "No tienes permisos para hacer esta reserva"}), 403
        
        # --- Buscar usuario y actividad ---
        user = db.users.find_one({"id": id_usuario})
        activity = db.activities.find_one({"id": id_actividad})
        
        # --- Si no se encuentra el usuario o la actividad, se devuelve error ---
        if not user:

            return jsonify({"error": "Usuario no encontrado"}), 404

        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Si la actividad ya ha acabado, se devuelve error ---
        if activity["state"] != "active":

            return jsonify({"error": "La actividad no está activa"}), 400
        
        # --- Si no quedan plazas disponibles, se devuelve error ---
        if len(activity.get("users", [])) >= activity["capacity"]:

            return jsonify({"error": "La actividad está llena"}), 400
        
        # --- Verificar si ya existe una reserva para esta actividad ---
        existing_booking = None
        for booking in user.get("bookings", []):

            if booking["activity_id"] == id_actividad:

                existing_booking = booking
                break
        
        # --- Si existe una reserva activa (no cancelada), no permitir duplicado ---
        if existing_booking and existing_booking.get("activity_state") not in ["cancel", "no assist"]:

            return jsonify({"error": "Ya tienes una reserva activa para esta actividad"}), 409
        
        # --- Comprobar si esta reserva se pisa con otra ---
        if check_time_overlap(user.get("bookings", []), activity["start"], activity["finish"], id_actividad):

            return jsonify({"error": "Tienes otra reserva durante este horario"}), 409
        
        # --- Crear la nueva reserva ---
        new_booking = {

            "activity_id": id_actividad,
            "activity_state": "assist",     # --- Por defecto, se asume que el usuario asiste a la actividad ---
            "booked_at": datetime.now(UTC) 

        }
        
        # --- Si ya existe una reserva cancelada es esta actividad, se actualiza ---
        if existing_booking:

            db.users.update_one(

                {"id": id_usuario, "bookings.activity_id": id_actividad},
                {"$set": {

                    "bookings.$.activity_state": "assist",
                    "bookings.$.booked_at": datetime.now(UTC)

                }}

            )

        else:
            # --- Si no existe ninguna reserva en esta actividad, se añade ---
            db.users.update_one(

                {"id": id_usuario},
                {"$push": {"bookings": new_booking}}

            )
        
        # --- Se añade al usuario a la lista de asistentes de la actividad ---
        db.activities.update_one(

            {"id": id_actividad},
            {"$addToSet": {"users": user["username"]}}

        )
        
        # --- Se devuelve mensaje de éxito ---
        return jsonify({"message": "Actividad reservada exitosamente"}), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:
        
        return jsonify({"error": str(e)}), 500


# --- DELETE /api/users/<int:id_usuario>/bookings/<int:id_actividad> -> Cancelar una reserva ---
@app.route('/api/users/<int:id_usuario>/bookings/<int:id_actividad>', methods = ['DELETE'])
@token_required
def cancel_activity(current_user, id_usuario, id_actividad):

    try:
        # --- Verificar permisos: solo puede cancelar su propia reserva y los admin pueden cancelar cualquier reserva ---
        if current_user["id"] != id_usuario and current_user["role"] != "admin":

            return jsonify({"error": "No tienes permisos para cancelar esta reserva"}), 403
        
        # --- Buscar el usuario y la actividad ---
        user = db.users.find_one({"id": id_usuario})
        activity = db.activities.find_one({"id": id_actividad})
        
        # --- Si no se encuentra el usuario o la actividad, se devuelve error ---
        if not user:

            return jsonify({"error": "Usuario no encontrado"}), 404

        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Se busca la reserva ---
        booking = None

        for book in user.get("bookings", []):

            if book["activity_id"] == id_actividad:

                booking = book
                break
        
        # --- Si no se encuentra la reserva, se devuelve error ---
        if not booking:

            return jsonify({"error": "Reserva no encontrada"}), 404
        
        # --- Verificar que la reserva no esté ya cancelada ---
        if booking.get("activity_state") in ["cancel", "no assist"]:

            return jsonify({"error": "La reserva ya está cancelada"}), 400
        
        # --- Calcular tiempo hasta el inicio de la actividad ---
        activity_start = activity["start"]
        time_until_start = activity_start - datetime.now(UTC).replace(tzinfo=None) # MongoDB dates are naive but UTC usually
        
        # --- Si cancela antes de 15min, se cancela pero si queda menos de 15min, se marca como no asistido ---
        if time_until_start > timedelta(minutes = 15):

            new_state = "cancel"

        else:

            new_state = "no assist"
        
        # --- Se actualiza el estado de la reserva ---
        db.users.update_one(

            {"id": id_usuario, "bookings.activity_id": id_actividad},
            {"$set": {"bookings.$.activity_state": new_state}}

        )
        
        # --- Si es una cancelación limpia (más de 15min), se elimina el usuario de la actividad ---
        if new_state == "cancel":

            db.activities.update_one(

                {"id": id_actividad},
                {"$pull": {"users": user["username"]}}

            )
        # --- Si es no assist (menos de 15min), NO se elimina para que la plaza siga ocupada ---
        else:

            # --- El usuario permanece en activity["users"] ---
            pass
        
        # --- Se devuelve mensaje de éxito ---
        return jsonify({
            
            "message": f"Actividad cancelada con estado: {new_state}",
            "state": new_state

        }), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- PUT /api/users/<int:id_usuario>/bookings/<int:id_actividad>/attend -> Marcar asistencia (solo admin) ---
@app.route('/api/users/<int:id_usuario>/bookings/<int:id_actividad>/attend', methods = ['PUT'])
@token_required
@admin_required
def mark_attendance(current_user, id_usuario, id_actividad):

    try:

        # --- Buscar el usuario y la actividad ---
        user = db.users.find_one({"id": id_usuario})
        activity = db.activities.find_one({"id": id_actividad})
        
        # --- Si no se encuentra el usuario o la actividad, se devuelve error ---
        if not user:

            return jsonify({"error": "Usuario no encontrado"}), 404

        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Buscar la reserva ---
        booking = None

        for book in user.get("bookings", []):

            if book["activity_id"] == id_actividad:

                booking = book
                break
        
        # --- Si no se encuentra la reserva, se devuelve error ---
        if not booking:

            return jsonify({"error": "Reserva no encontrada"}), 404
        
        # --- Marcar asistencia ---
        db.users.update_one(

            {"id": id_usuario, "bookings.activity_id": id_actividad},
            {"$set": {"bookings.$.activity_state": "assist"}}

        )
        
        # --- Se devuelve mensaje de éxito ---
        return jsonify({"message": "Asistencia marcada exitosamente"}), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- GET /api/activities -> Obtener todas las actividades ---
@app.route('/api/activities', methods = ['GET'])
@token_required
def get_all_activities(current_user):

    try:
        
        # --- Iniciar variable para el filtro de la consulta ---
        filter_query = {}
        
        # --- Si se pasa el estado de la actividad, se aplica el filtro a la consulta ---
        state = request.args.get('state')

        if state:

            filter_query["state"] = state
        
        # --- Obtener actividades ---
        activities = list(db.activities.find(filter_query, {"_id": 0}))
        
        # --- Si se pasa el parámetro "available", se filtran las actividades disponibles ---
        available = request.args.get('available')

        if available and available.lower() == 'true':

            activities = [

                activity for activity in activities
                if len(activity.get("users", [])) < activity["capacity"]

            ]
        
        # --- Convertir fechas a string ISO con el sufijo 'Z' para el frontend ---
        for activity in activities:

            activity["start"] = format_date_utc(activity.get("start"))
            activity["finish"] = format_date_utc(activity.get("finish"))

        # --- Se devuelve la lista de actividades ---
        return jsonify(activities), 200

    # --- Si hay algún error, se devuelve --- 
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- GET /api/activities/<int:id_actividad> -> Obtener actividad por ID ---
@app.route('/api/activities/<int:id_actividad>', methods = ['GET'])
@token_required
def get_activity(current_user, id_actividad):

    try:

        # --- Buscar actividad ---
        activity = db.activities.find_one({"id": id_actividad}, {"_id": 0})
        
        # --- Si no se encuentra la actividad, se devuelve error ---
        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Convertir fechas a string ISO con el sufijo 'Z' ---
        activity["start"] = format_date_utc(activity.get("start"))
        activity["finish"] = format_date_utc(activity.get("finish"))

        # --- Se devuelve la actividad ---
        return jsonify(activity), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- POST /api/activities -> Crear actividad (solo admin) ---
@app.route('/api/activities', methods = ['POST'])
@token_required
@admin_required
def create_activity(current_user):

    try:

        # --- Obtener datos de la actividad (del form data si hay archivo, o json) ---
        if request.content_type and 'multipart/form-data' in request.content_type:

            data = request.form

        else:

            data = request.json or {}
        
        # --- Validar campos requeridos ---
        required_fields = ["name", "description", "start", "finish", "capacity"]

        # --- Si algún campo requerido no se encuentra, se devuelve error ---
        for field in required_fields:

            if field not in data:

                return jsonify({"error": f"El campo {field} es requerido"}), 400
        
        # --- Convertir fechas de string (en formato iso) a datetime ---
        try:

            start = data["start"]
            finish = data["finish"]
            
            # --- Limpiar comillas extra si vienen del form data ---
            if isinstance(start, str): start = start.strip('"')
            if isinstance(finish, str): finish = finish.strip('"')

            # --- Convertir fechas a formato datetime ---
            start_date = datetime.fromisoformat(start.replace('Z', '+00:00'))
            finish_date = datetime.fromisoformat(finish.replace('Z', '+00:00'))

        # --- Si el formato de la fecha es inválido, se devuelve error ---
        except ValueError:

            return jsonify({"error": "Formato de fecha inválido. Usar formato ISO 8601"}), 400
        
        # --- Validar que la fecha de inicio sea posterior a la actual ---
        if start_date <= datetime.now(UTC):

            return jsonify({"error": "La fecha de inicio debe ser posterior a la fecha y hora actuales"}), 400

        # --- Validar que la fecha de fin sea posterior a la de inicio ---
        if finish_date <= start_date:

            return jsonify({"error": "La fecha de fin debe ser posterior a la de inicio"}), 400
        
        # --- Procesar imagen ---
        image_filename = None
        if 'image' in request.files:

            file = request.files['image']

            if file and file.filename != '' and allowed_file(file.filename):

                filename = secure_filename(file.filename)
                
                # --- Añadir timestamp al nombre para evitar duplicados ---
                timestamp = int(datetime.now(UTC).timestamp())
                filename = f"{timestamp}_{filename}"
                
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename
        
        # --- Crear nueva actividad ---
        new_activity = {

            "id": get_next_id("activities"),
            "name": data["name"],
            "description": data["description"],
            "start": start_date,
            "finish": finish_date,
            "state": data.get("state", "active"),
            "image": image_filename,
            "users": [],
            "capacity": int(data["capacity"])

        }
        
        # --- Insertar la actividad en la base de datos ---
        db.activities.insert_one(new_activity)
        
        # --- Quitar id de mongo ---
        new_activity.pop("_id")
        
        # --- Formatear fechas para la respuesta ---
        new_activity["start"] = format_date_utc(new_activity.get("start"))
        new_activity["finish"] = format_date_utc(new_activity.get("finish"))

        # --- Se devuelve mensaje de éxito ---
        return jsonify({

            "message": "Actividad creada exitosamente",
            "activity": new_activity

        }), 201
        
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- PUT /api/activities/<int:id_actividad> -> Modificar actividad (solo admin) ---
@app.route('/api/activities/<int:id_actividad>', methods = ['PUT'])
@token_required
@admin_required
def update_activity(current_user, id_actividad):

    try:

        # --- Obtener datos de la petición (del form data si hay archivo, o json) ---
        if request.content_type and 'multipart/form-data' in request.content_type:

            data = request.form
            
        else:

            data = request.json or {}

        name = data.get("name")
        description = data.get("description")
        start = data.get("start")
        finish = data.get("finish")
        capacity = data.get("capacity")
        state = data.get("state")
        
        # --- Validar que se envíen todos los campos ---
        if not name or not description or not start or not finish or not capacity or not state:

            return jsonify({"error": "Completa todos los campos"}), 400
        
        # --- Buscar actividad ---
        activity = db.activities.find_one({"id": id_actividad})
        
        # --- Si no se encuentra la actividad, se devuelve error ---
        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Convertir fechas de string (formato iso) a datetime ---
        try:
            
            # --- Limpiar comillas extra si vienen del form data ---
            if isinstance(start, str): start = start.strip('"')
            if isinstance(finish, str): finish = finish.strip('"')
            
            start_date = datetime.fromisoformat(start.replace('Z', '+00:00'))
            finish_date = datetime.fromisoformat(finish.replace('Z', '+00:00'))
        
        # --- Si el formato de fecha es inválido, se devuelve error ---
        except ValueError:

            return jsonify({"error": "Formato de fecha inválido. Usar formato ISO 8601"}), 400
        
        # --- Validar que la fecha de inicio sea posterior a la actual ---
        if start_date <= datetime.now(UTC):

            return jsonify({"error": "La fecha de inicio debe ser posterior a la fecha y hora actuales"}), 400

        # --- Validar que la fecha de fin sea posterior a la de inicio ---
        if finish_date <= start_date:

            return jsonify({"error": "La fecha de fin debe ser posterior a la de inicio"}), 400
        
        # --- Procesar imagen (si se envía una nueva) ---
        image_filename = activity.get("image")
        
        if 'image' in request.files:

            file = request.files['image']

            if file and file.filename != '' and allowed_file(file.filename):

                # --- Borrar imagen anterior si existe ---
                if image_filename:

                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)

                    if os.path.exists(old_image_path):

                        os.remove(old_image_path)
                
                filename = secure_filename(file.filename)

                # --- Añadir timestamp para evitar duplicados ---
                timestamp = int(datetime.now(UTC).timestamp())
                filename = f"{timestamp}_{filename}"

                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename

        # --- Definir campos con los nuevos valores ---
        update_fields = {

            "name": name,
            "description": description,
            "start": start_date,
            "finish": finish_date,
            "capacity": int(capacity),
            "state": state,
            "image": image_filename

        }
        
        # --- Actualizar la actividad en la base de datos ---
        db.activities.update_one({"id": id_actividad}, {"$set": update_fields})
        
        # --- Devolver actividad actualizada (sin id de Mongo) ---
        updated_activity = db.activities.find_one({"id": id_actividad}, {"_id": 0})
        
        # --- Formatear fechas para la respuesta ---
        if updated_activity:

            updated_activity["start"] = format_date_utc(updated_activity.get("start"))
            updated_activity["finish"] = format_date_utc(updated_activity.get("finish"))

        # --- Devolver mensaje de éxito ---
        return jsonify({

            "message": "Actividad actualizada exitosamente",
            "activity": updated_activity

        }), 200
        
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- DELETE /api/activities/<int:id_actividad> -> Eliminar actividad (solo admin) ---
@app.route('/api/activities/<int:id_actividad>', methods = ['DELETE'])
@token_required
@admin_required
def delete_activity(current_user, id_actividad):

    try:

        # --- Buscar la actividad ---
        activity = db.activities.find_one({"id": id_actividad})
        
        # --- Si no se encuentra la actividad, se devuelve error ---
        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Borrar imagen si existe ---
        image_filename = activity.get("image")
        if image_filename:

            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)

            if os.path.exists(image_path):
                
                os.remove(image_path)
        
        # --- Eliminar la actividad de las reservas de todos los usuarios ---
        db.users.update_many(

            {"bookings.activity_id": id_actividad},
            {"$pull": {"bookings": {"activity_id": id_actividad}}}

        )
        
        # --- Eliminar la actividad ---
        db.activities.delete_one({"id": id_actividad})
        
        # --- Devolver mensaje de éxito ---
        return jsonify({"message": "Actividad eliminada exitosamente"}), 200
        
    except Exception as e:
        
        # --- Si hay algún error, se devuelve ---
        return jsonify({"error": str(e)}), 500


# --- GET /api/activities/<int:id_actividad>/attendees -> Obtener asistentes de actividad (solo admin) ---
@app.route('/api/activities/<int:id_actividad>/attendees', methods = ['GET'])
@token_required
@admin_required
def get_activity_attendees(current_user, id_actividad):

    try:

        # --- Buscar la actividad ---
        activity = db.activities.find_one({"id": id_actividad})
        
        # --- Si no se encuentra la actividad, se devuelve error ---
        if not activity:

            return jsonify({"error": "Actividad no encontrada"}), 404
        
        # --- Obtener información completa de cada asistente ---
        attendees = []
        for username in activity.get("users", []):

            # --- Buscar al usuario ---
            user = db.users.find_one({"username": username})

            # --- Si se encuentra al usuario, se agrega a la lista ---
            if user:

                attendees.append(user)
        
        # --- Devolver información de la actividad y sus asistentes ---
        return jsonify({

            "activity_id": id_actividad,
            "activity_name": activity["name"],
            "total_attendees": len(attendees),
            "capacity": activity["capacity"],
            "attendees": attendees

        }), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500

# --- GET /api/bookings -> Obtener todas las reservas (solo admin) ---
@app.route('/api/bookings', methods = ['GET'])
@token_required
@admin_required
def get_all_bookings(current_user):

    try:

        # --- Obtener todos los usuarios que tienen reservas ---
        users_with_bookings = list(db.users.find({"bookings": {"$exists": True, "$not": {"$size": 0}}}, {"_id": 0, "password": 0}))
        
        all_bookings = []

        # --- Buscar todas las actividades para evitar N+1 queries ---
        activities_list = list(db.activities.find({}, {"_id": 0}))
        activities_map = {a["id"]: a for a in activities_list}

        # --- Recorrer cada usuario y sus reservas ---
        for user in users_with_bookings:

            for booking in user.get("bookings", []):

                # --- Buscar la actividad en el mapa ---
                activity = activities_map.get(booking["activity_id"])
                
                if activity:

                    # --- Enriquecer la reserva con datos del usuario y de la actividad ---
                    all_bookings.append({

                        "user_id": user["id"],
                        "user_name": user["name"],
                        "username": user["username"],
                        "activity_id": booking["activity_id"],
                        "activity_name": activity["name"],
                        "activity_start": (activity["start"].isoformat() + "Z") if isinstance(activity["start"], datetime) else activity["start"],
                        "activity_finish": (activity["finish"].isoformat() + "Z") if isinstance(activity["finish"], datetime) else activity["finish"],
                        "activity_state": booking["activity_state"],
                        "booked_at": (booking.get("booked_at").isoformat() + "Z") if isinstance(booking.get("booked_at"), datetime) else booking.get("booked_at")

                    })
        
        # --- Devolver la lista completa de reservas ---
        return jsonify(all_bookings), 200
    
    # --- Si hay algún error, se devuelve ---
    except Exception as e:

        return jsonify({"error": str(e)}), 500


# --- Inicio de la aplicación ---
if __name__ == '__main__':

    # --- En Windows, el reloader por defecto puede dar problemas con select() ---
    # --- Forzamos el uso de 'stat' que es mas estable en algunos entornos ---
    app.run(debug = True, host = '0.0.0.0', port = 5000, use_reloader = True)