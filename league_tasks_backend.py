import os
import sqlite3
import requests
import time
import pytz
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from threading import Lock
from champions import champions
from functools import wraps
from flask import abort
from items import item_list
from runes import RUNES
from spells import SPELLS

# Leer los nombres de las bases de datos desde las variables de entorno
LEAGUE_TASKS_DB = os.getenv('LEAGUE_TASKS_DB', 'league_tasks.db')
MATCH_HISTORY_DB = os.getenv('MATCH_HISTORY_DB', 'match_history.db')


# Adaptadores personalizados para datetime
def adapt_datetime(dt):
    return dt.isoformat()

def convert_timestamp(ts):
    return datetime.fromisoformat(ts.decode('utf-8'))

# Registrar adaptadores personalizados
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_timestamp)

# Configuración básica
API_KEY = "RGAPI-68903f6f-e823-4f62-993e-a68466928ba4"
SUMMONER_API_BASE_URL = "https://la1.api.riotgames.com"  # Base URL para datos del jugador (LAN)
MATCH_API_BASE_URL = "https://americas.api.riotgames.com"  # Base URL para datos de partidas
DB_NAME = "league_tasks.db"

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Bloqueo para la base de datos
db_lock = Lock()

# Clase de usuario
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# Formulario de inicio de sesión
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    submit = SubmitField('Login')

# Formulario de registro
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    submit = SubmitField('Register')

class UpdateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[Length(min=6, max=25)])
    puuid = StringField('PUUID', validators=[Length(min=0, max=78)])
    summoner_name = StringField('Summoner Name', validators=[Length(min=0, max=25)])
    submit = SubmitField('Update')

# Cargar usuario
@login_manager.user_loader
def load_user(user_id):
    user = query_db("SELECT id, username, password, role, puuid, summoner_name FROM users WHERE id = ?", (user_id,), one=True)
    if user:
        return User(user['id'], user['username'], user['password'], user['role'], user['puuid'], user['summoner_name'])
    return None

class User(UserMixin):
    def __init__(self, id, username, password, role, puuid=None, summoner_name=None):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.puuid = puuid
        self.summoner_name = summoner_name

    @staticmethod
    def get(user_id):
        user = query_db("SELECT id, username, password, role, puuid, summoner_name FROM users WHERE id = ?", (user_id,), one=True)
        if not user:
            return None
        return User(user['id'], user['username'], user['password'], user['role'], user['puuid'], user['summoner_name'])

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=10, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row  # Esto permite acceder a las columnas por nombre
    return conn

# Bloqueo para asegurar acceso concurrente seguro a la base de datos
db_lock = Lock()

# Función para obtener la conexión a la base de datos principal
def get_db():
    conn = sqlite3.connect('league_tasks.db', timeout=30, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row  # Esto permite acceder a las columnas por nombre
    return conn

# Función para obtener la conexión a la base de datos de historial de partidas
def get_match_history_db():
    conn = sqlite3.connect('match_history.db', timeout=30, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row  # Esto permite acceder a las columnas por nombre
    return conn

# Funciones auxiliares para la base de datos
def init_league_tasks_db():
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        
        # Crear tabla players si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS players (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                puuid TEXT UNIQUE,
                summoner_name TEXT UNIQUE,
                account_id TEXT,
                summoner_level INTEGER,
                profile_icon_id INTEGER,
                revision_date INTEGER,
                points INTEGER DEFAULT 0,
                last_update TIMESTAMP
            )
        ''')
        
        # Crear tabla tasks si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT,
                objective_type TEXT,
                target_value INTEGER,
                points INTEGER,
                champion INTEGER
            )
        ''')
        
        # Crear tabla assigned_tasks si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assigned_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_id INTEGER,
                task_id INTEGER,
                progress REAL DEFAULT 0,
                is_completed BOOLEAN DEFAULT 0,
                assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (player_id) REFERENCES players(id),
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            )
        ''')

        # Crear tabla player_stats si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS player_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                puuid TEXT,
                match_id TEXT,
                champion_id INTEGER,
                kills INTEGER,
                deaths INTEGER,
                assists INTEGER,
                win BOOLEAN,
                team_id INTEGER,
                gold INTEGER,
                damage INTEGER,
                turret_kills INTEGER DEFAULT 0,
                cs INTEGER DEFAULT 0,
                wards_placed INTEGER DEFAULT 0,
                atakhan_kills INTEGER DEFAULT 0,
                inhibitor_kills INTEGER DEFAULT 0,
                solo_kills INTEGER DEFAULT 0,
                dragons INTEGER DEFAULT 0,
                barons INTEGER DEFAULT 0,
                vision_score INTEGER DEFAULT 0,
                wards_destroyed INTEGER DEFAULT 0,
                wins INTEGER DEFAULT 0,
                match_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (puuid) REFERENCES players(puuid)
            )
        ''')

        conn.commit()
        conn.close()

    # Verificar y agregar columnas faltantes
    check_and_add_column()

def init_match_history_db():
    with db_lock:
        conn = get_match_history_db()
        cursor = conn.cursor()
        
        # Crear tabla match_history si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS match_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_id TEXT UNIQUE,
                puuid TEXT,
                match_date TIMESTAMP,
                champion_id INTEGER,
                kills INTEGER,
                deaths INTEGER,
                assists INTEGER,
                total_gold INTEGER,
                lane TEXT,
                primary_runes TEXT,
                secondary_runes TEXT,
                spells TEXT,
                items TEXT,
                win BOOLEAN,
                FOREIGN KEY (puuid) REFERENCES players(puuid)
            )
        ''')

        # Crear tabla champion_stats si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS champion_stats (
                puuid TEXT,
                champion_id INTEGER,
                games_played INTEGER,
                total_kills INTEGER,
                total_deaths INTEGER,
                total_assists INTEGER,
                total_wins INTEGER,
                total_gold INTEGER,
                total_damage INTEGER,
                PRIMARY KEY (puuid, champion_id)
            )
        ''')

        # Crear tabla processed_matches si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_matches (
                match_id TEXT PRIMARY KEY
            )
        ''')

        conn.commit()
        conn.close()

def create_player_stats_table():
    conn = sqlite3.connect('league_tasks.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS player_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            puuid TEXT,
            match_id TEXT,
            champion_id INTEGER,
            kills INTEGER,
            deaths INTEGER,
            assists INTEGER,
            win BOOLEAN,
            team_id INTEGER,
            gold INTEGER,
            damage INTEGER,
            turret_kills INTEGER DEFAULT 0,
            cs INTEGER DEFAULT 0,
            wards_placed INTEGER DEFAULT 0,
            atakhan_kills INTEGER DEFAULT 0,
            inhibitor_kills INTEGER DEFAULT 0,
            solo_kills INTEGER DEFAULT 0,
            dragons INTEGER DEFAULT 0,
            barons INTEGER DEFAULT 0,
            vision_score INTEGER DEFAULT 0,
            wards_destroyed INTEGER DEFAULT 0,
            wins INTEGER DEFAULT 0,
            game_time INTEGER DEFAULT 0,
            total_team_kills INTEGER DEFAULT 0,
            match_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (puuid) REFERENCES players(puuid)
        )
    ''')
    conn.commit()
    conn.close()

def add_game_time_column():
    create_player_stats_table()
    conn = sqlite3.connect('league_tasks.db')
    cursor = conn.cursor()
    
    # Verificar si la columna game_time ya existe
    cursor.execute("PRAGMA table_info(player_stats)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'game_time' not in columns:
        cursor.execute("ALTER TABLE player_stats ADD COLUMN game_time INTEGER DEFAULT 0")
    
    conn.commit()
    conn.close()

add_game_time_column()

def add_total_team_kills_column():
    create_player_stats_table()
    conn = sqlite3.connect('league_tasks.db')
    cursor = conn.cursor()
    
    # Verificar si la columna total_team_kills ya existe
    cursor.execute("PRAGMA table_info(player_stats)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'total_team_kills' not in columns:
        cursor.execute("ALTER TABLE player_stats ADD COLUMN total_team_kills INTEGER DEFAULT 0")
    
    conn.commit()
    conn.close()

add_total_team_kills_column()

def migrate_db():
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()

        # Verificar si la columna match_id existe en match_history, si no, agregarla
        cursor.execute("PRAGMA table_info(match_history)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'match_id' not in columns:
            cursor.execute("ALTER TABLE match_history ADD COLUMN match_id TEXT UNIQUE")

        # Verificar si las columnas necesarias existen en player_stats
        cursor.execute("PRAGMA table_info(player_stats)")
        columns = [column[1] for column in cursor.fetchall()]
        required_columns = [
            'kills', 'deaths', 'assists', 'turret_kills', 'cs', 'wards_placed', 'atakhan_kills',
            'inhibitor_kills', 'solo_kills', 'dragons', 'barons', 'vision_score', 'wards_destroyed', 'wins'
        ]
        for col in required_columns:
            if col not in columns:
                cursor.execute(f"ALTER TABLE player_stats ADD COLUMN {col} INTEGER DEFAULT 0")

        conn.commit()
        conn.close()

# Llamar a la función de migración antes de iniciar la aplicació

def update_user_roles():
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()

        # Aquí puedes agregar la lógica para actualizar los roles de los usuarios
        # Por ejemplo, podrías actualizar el rol de un usuario específico
        cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")

        conn.commit()
        conn.close()

def query_db(query, args=(), one=False, db='league_tasks'):
    with db_lock:
        if db == 'league_tasks':
            conn = get_db()
        elif db == 'match_history':
            conn = get_match_history_db()
        else:
            raise ValueError("Invalid database specified")

        cursor = conn.execute(query, args)
        rv = cursor.fetchall()
        cursor.close()
        conn.commit()
        conn.close()
        return (rv[0] if rv else None) if one else rv
    
def check_and_add_column():
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        
        # Verificar si las columnas necesarias existen en player_stats
        cursor.execute("PRAGMA table_info(player_stats)")
        columns = [column[1] for column in cursor.fetchall()]
        required_columns = [
            'turret_kills', 'cs', 'wards_placed', 'atakhan_kills', 'inhibitor_kills',
            'solo_kills', 'dragons', 'barons', 'vision_score', 'wards_destroyed', 'wins', 'match_date'
        ]
        for col in required_columns:
            if col not in columns:
                if col == 'match_date':
                    cursor.execute(f"ALTER TABLE player_stats ADD COLUMN {col} TIMESTAMP")
                else:
                    cursor.execute(f"ALTER TABLE player_stats ADD COLUMN {col} INTEGER DEFAULT 0")

        # Actualizar los valores de la columna match_date a CURRENT_TIMESTAMP si es necesario
        if 'match_date' not in columns:
            cursor.execute("UPDATE player_stats SET match_date = CURRENT_TIMESTAMP WHERE match_date IS NULL")

        conn.commit()
        conn.close()

def match_ids(summoner_name):
    # Obtener el PUUID del jugador
    summoner_url = f"{MATCH_API_BASE_URL}/lol/summoner/v4/summoners/by-name/{summoner_name}"
    headers = {"X-Riot-Token": API_KEY}
    summoner_response = requests.get(summoner_url, headers=headers)

    if summoner_response.status_code != 200:
        return []

    summoner_data = summoner_response.json()
    puuid = summoner_data['puuid']

    # Obtener los IDs de las partidas
    matchlist_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/by-puuid/{puuid}/ids"
    matchlist_response = requests.get(matchlist_url, headers=headers)

    if matchlist_response.status_code != 200:
        return []

    match_ids = matchlist_response.json()
    return match_ids

# Registro del filtro personalizado
@app.template_filter('multiply')
def multiply(value, factor):
    return value * factor

# Registro del filtro personalizado
@app.template_filter('min_value')
def min_value(value, arg):
    return min(value, arg)

# Rutas de la aplicación
@app.route('/')
@login_required
def index():
    return render_template('index.html')


# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = query_db("SELECT id, username, password, role FROM users WHERE username = ?", (form.username.data,), one=True)
        if user and user[2] == form.password.data:
            login_user(User(user[0], user[1], user[2], user[3]))
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Verificar si el usuario ya existe
        existing_user = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))

        # Insertar el nuevo usuario en la base de datos con el rol 'user' por defecto
        query_db("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, 'user'))
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Ruta de cierre de sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = query_db("SELECT id, username, role FROM users")
    print(users)
    return render_template('admin_dashboard.html', users=users)

@app.route('/delete-user', methods=['POST'])
@login_required
@admin_required
def delete_user():
    user_id = request.form.get('user_id')
    if user_id:
        query_db("DELETE FROM users WHERE id = ?", (user_id,))
        flash('User deleted successfully.')
    else:
        flash('Failed to delete user.')
    return redirect(url_for('admin_dashboard'))

@app.route('/tasks', methods=['POST', 'GET'])
@login_required
@admin_required
def manage_tasks():
    if request.method == 'POST':
        if 'delete_task' in request.form:
            task_id = request.form.get('task_id')
            if not task_id:
                flash("Faltan datos para eliminar la tarea.")
                return redirect(url_for('manage_tasks'))

            # Eliminar las asignaciones de la tarea a los jugadores
            query_db("DELETE FROM assigned_tasks WHERE task_id = ?", (task_id,))
            # Eliminar la tarea
            query_db("DELETE FROM tasks WHERE id = ?", (task_id,))
            flash("Tarea eliminada con éxito.")
        else:
            description = request.form.get('description')
            objective_type = request.form.get('objective_type')
            target_value = request.form.get('target_value')
            points = request.form.get('points')
            champion = request.form.get('champion')

            # Verificar si el ID del campeón es válido
            if champion and not champion.isdigit():
                flash("El ID del campeón debe ser un número.")
                return redirect(url_for('manage_tasks'))

            query_db("""
                INSERT INTO tasks (description, objective_type, target_value, points, champion)
                VALUES (?, ?, ?, ?, ?)
            """, (description, objective_type, target_value, points, int(champion) if champion else None))

            flash("Tarea creada con éxito")
        
        return redirect(url_for('manage_tasks'))

    elif request.method == 'GET':
        tasks = query_db("SELECT id, description, objective_type, target_value, points, champion FROM tasks")
        return render_template('tasks.html', tasks=tasks)

    elif request.method == 'GET':
        tasks = query_db("SELECT id, description, objective_type, target_value, points, champion FROM tasks")
        return render_template('tasks.html', tasks=tasks)


# Ruta para registrar jugadores
@app.route('/register-player', methods=['POST', 'GET'])
@login_required
@admin_required
def register_player():
    if request.method == 'POST':
        encrypted_puuid = request.form.get('encrypted_puuid')
        summoner_name = request.form.get('summoner_name')

        # Consultar Riot API para obtener información del jugador usando el PUUID
        url = f"{SUMMONER_API_BASE_URL}/lol/summoner/v4/summoners/by-puuid/{encrypted_puuid}"
        headers = {"X-Riot-Token": API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            flash("No se pudo obtener información del jugador.")
            return redirect(url_for('register_player'))

        summoner_data = response.json()
        puuid = summoner_data.get('puuid')
        summoner_name = summoner_data.get('name') or summoner_name
        account_id = summoner_data.get('accountId')
        summoner_level = summoner_data.get('summonerLevel')
        profile_icon_id = summoner_data.get('profileIconId')
        revision_date = summoner_data.get('revisionDate')

        if not puuid or not summoner_name:
            flash("Datos incompletos obtenidos de la API de Riot.")
            return redirect(url_for('register_player'))

        try:
            query_db("""
                INSERT INTO players (puuid, summoner_name, account_id, summoner_level, profile_icon_id, revision_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (puuid, summoner_name, account_id, summoner_level, profile_icon_id, revision_date))
            flash("Jugador registrado con éxito")
        except sqlite3.IntegrityError:
            flash("El jugador ya está registrado")
            return redirect(url_for('register_player'))

        return redirect(url_for('register_player'))

    players = query_db("SELECT summoner_name, puuid FROM players")
    return render_template('register_player.html', players=players)

# Endpoint: Asignar tareas a jugadores
@app.route('/assign-task', methods=['POST', 'GET'])
@login_required
@admin_required
def assign_task():
    if request.method == 'POST':
        summoner_name = request.form.get('summoner_name')
        task_id = request.form.get('task_id')

        player = query_db("SELECT id, puuid FROM players WHERE summoner_name = ?", (summoner_name,), one=True)
        if not player:
            flash("Jugador no encontrado")
            return redirect(url_for('assign_task'))

        player_id = player['id']
        puuid = player['puuid']
        query_db("INSERT INTO assigned_tasks (player_id, task_id) VALUES (?, ?)", (player_id, task_id))

        flash("Tarea asignada con éxito")
        return redirect(url_for('assign_task'))

    tasks = query_db("SELECT id, description FROM tasks")
    players = query_db("SELECT summoner_name FROM players")
    return render_template('assign_task.html', tasks=tasks, players=players)

def get_player_stats(puuid, last_update):
    # Obtener estadísticas acumuladas existentes
    existing_stats_row = query_db("""
        SELECT SUM(kills) as kills, SUM(deaths) as deaths, SUM(assists) as assists, SUM(turret_kills) as turret_kills,
               SUM(cs) as cs, SUM(damage) as damage, SUM(wins) as wins, COUNT(*) as games, SUM(wards_placed) as wards_placed,
               SUM(gold) as gold, SUM(atakhan_kills) as atakhan_kills, SUM(inhibitor_kills) as inhibitor_kills,
               SUM(solo_kills) as solo_kills, SUM(dragons) as dragons, SUM(barons) as barons, SUM(vision_score) as vision_score,
               SUM(wards_destroyed) as wards_destroyed, SUM(game_time) as game_time, MAX(champion_id) as champion_id,
               SUM(total_team_kills) as total_team_kills
        FROM player_stats
        WHERE puuid = ?
    """, (puuid,), one=True)

    existing_stats = {key: (value if value is not None else 0) for key, value in dict(existing_stats_row).items()} if existing_stats_row else {
        'kills': 0,
        'deaths': 0,
        'assists': 0,
        'turret_kills': 0,
        'cs': 0,
        'damage': 0,
        'wins': 0,
        'games': 0,
        'wards_placed': 0,
        'gold': 0,
        'atakhan_kills': 0,
        'inhibitor_kills': 0,
        'solo_kills': 0,
        'dragons': 0,
        'barons': 0,
        'vision_score': 0,
        'wards_destroyed': 0,
        'game_time': 0,
        'champion_id': 0,
        'total_team_kills': 0,
        'average_cs_per_min': 0,
        'kill_participation': 0,
        'vision_score_per_min': 0,
        'kda': 0  # Asegurarse de que esta clave esté presente
    }

    match_list_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/by-puuid/{puuid}/ids?start=0&count=40"
    headers = {"X-Riot-Token": API_KEY}
    match_list_response = requests.get(match_list_url, headers=headers)

    if match_list_response.status_code != 200:
        return existing_stats

    match_ids = match_list_response.json()
    new_stats = {
        'kills': 0,
        'deaths': 0,
        'assists': 0,
        'turret_kills': 0,
        'cs': 0,
        'damage': 0,
        'wins': 0,
        'games': 0,
        'game_time': 0,
        'wards_placed': 0,
        'gold': 0,
        'atakhan_kills': 0,
        'inhibitor_kills': 0,
        'solo_kills': 0,
        'dragons': 0,
        'barons': 0,
        'champion_id': 0,
        'total_team_kills': 0,
        'vision_score': 0,
        'wards_destroyed': 0,
        'average_cs_per_min': 0,
        'vision_score_per_min': 0,
        'kda': 0  # Asegurarse de que esta clave esté presente
    }

    for match_id in match_ids:
        # Verificar si la partida ya ha sido procesada
        existing_match = query_db("SELECT 1 FROM player_stats WHERE match_id = ?", (match_id,), one=True)
        if existing_match:
            continue

        match_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/{match_id}"
        match_response = requests.get(match_url, headers=headers)

        if match_response.status_code != 200:
            continue

        match_data = match_response.json()
        queue_id = match_data['info']['queueId']

        # Verificar si la partida es clasificatoria
        is_ranked = queue_id in [420, 440]
        print(f"Match ID: {match_id}, Ranked: {is_ranked}")

        participants = match_data['info']['participants']
        player_stats = next((p for p in participants if p['puuid'] == puuid), None)

        if not player_stats:
            continue

        team_id = player_stats['teamId']
        team_kills = sum(p['kills'] for p in participants if p['teamId'] == team_id)

        new_stats['kills'] += player_stats.get('kills', 0)
        new_stats['deaths'] += player_stats.get('deaths', 0)
        new_stats['assists'] += player_stats.get('assists', 0)
        new_stats['turret_kills'] += player_stats.get('turretKills', 0)
        new_stats['cs'] += player_stats.get('totalMinionsKilled', 0) + player_stats.get('neutralMinionsKilled', 0)
        new_stats['damage'] += player_stats.get('totalDamageDealtToChampions', 0)
        new_stats['games'] += 1
        new_stats['game_time'] += match_data['info']['gameDuration']
        new_stats['wards_placed'] += player_stats.get('wardsPlaced', 0)
        new_stats['gold'] += player_stats.get('goldEarned', 0)
        new_stats['atakhan_kills'] += player_stats.get('challenges', {}).get('atakhanKills', 0)
        new_stats['inhibitor_kills'] += player_stats.get('inhibitorKills', 0)
        new_stats['solo_kills'] += player_stats.get('challenges', {}).get('soloKills', 0)
        new_stats['dragons'] += player_stats.get('dragonKills', 0)
        new_stats['barons'] += player_stats.get('baronKills', 0)
        new_stats['champion_id'] = player_stats.get('championId', 0)
        new_stats['total_team_kills'] += team_kills
        new_stats['vision_score'] += player_stats.get('visionScore', 0)
        new_stats['wards_destroyed'] += player_stats.get('wardTakedowns', 0)

        # Determinar si el equipo del jugador ganó
        team_won = any(team['win'] for team in match_data['info']['teams'] if team['teamId'] == team_id)
        if team_won:
            new_stats['wins'] += 1

        # Insertar datos en la tabla player_stats
        query_db("INSERT INTO player_stats (puuid, match_id, champion_id, kills, deaths, assists, win, team_id, gold, damage, turret_kills, cs, wards_placed, atakhan_kills, inhibitor_kills, solo_kills, dragons, barons, vision_score, wards_destroyed, game_time, match_date, total_team_kills) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (puuid, match_id, player_stats.get('championId', 0), player_stats.get('kills', 0), player_stats.get('deaths', 0), player_stats.get('assists', 0), team_won, player_stats.get('teamId', 0), player_stats.get('goldEarned', 0), player_stats.get('totalDamageDealtToChampions', 0), player_stats.get('turretKills', 0), player_stats.get('totalMinionsKilled', 0) + player_stats.get('neutralMinionsKilled', 0), player_stats.get('wardsPlaced', 0), player_stats.get('challenges', {}).get('atakhanKills', 0), player_stats.get('inhibitorKills', 0), player_stats.get('challenges', {}).get('soloKills', 0), player_stats.get('dragonKills', 0), player_stats.get('baronKills', 0), player_stats.get('visionScore', 0), player_stats.get('wardTakedowns', 0), match_data['info']['gameDuration'], datetime.fromtimestamp(match_data['info']['gameCreation'] / 1000), team_kills))

    # Acumular estadísticas existentes con las nuevas estadísticas
    for key in new_stats:
        if key in existing_stats:
            existing_stats[key] += new_stats[key]
        else:
            existing_stats[key] = new_stats[key]

    # Calcular visionScorePerMinute acumulado
    if existing_stats['game_time'] > 0:
        existing_stats['vision_score_per_min'] = round(existing_stats['vision_score'] / (existing_stats['game_time'] / 60), 2)

    # Calcular KDA
    existing_stats['kda'] = round((existing_stats['kills'] + existing_stats['assists']) / max(1, existing_stats['deaths']), 2)

    # Calcular CS por minuto
    existing_stats['average_cs_per_min'] = round((existing_stats['cs'] / (existing_stats['game_time'] / 60)), 2) if existing_stats['game_time'] > 0 else 0

    # Calcular participación en asesinatos
    if existing_stats['total_team_kills'] > 0:
        existing_stats['kill_participation'] = round(((existing_stats['kills'] + existing_stats['assists']) / existing_stats['total_team_kills']) * 100, 2)
    else:
        existing_stats['kill_participation'] = 0

    # Calcular win ratio
    existing_stats['win_ratio'] = round((existing_stats['wins'] / max(1, existing_stats['games'])) * 100, 2) if existing_stats['games'] > 0 else 0.0

    print(f"Stats: {existing_stats}")

    return existing_stats

def get_champion_stats(puuid, champion_id):
    stats = query_db("""
        SELECT SUM(kills) as kills, SUM(deaths) as deaths, SUM(assists) as assists, SUM(turret_kills) as turret_kills,
               SUM(cs) as cs, SUM(damage) as damage, SUM(wins) as wins, COUNT(*) as games, SUM(wards_placed) as wards_placed,
               SUM(gold) as gold, SUM(atakhan_kills) as atakhan_kills, SUM(inhibitor_kills) as inhibitor_kills,
               SUM(solo_kills) as solo_kills, SUM(dragons) as dragons, SUM(barons) as barons, SUM(vision_score) as vision_score,
               SUM(wards_destroyed) as wards_destroyed, SUM(game_time) as game_time
        FROM player_stats
        WHERE puuid = ? AND champion_id = ?
    """, (puuid, champion_id), one=True)

    if not stats:
        return {
            'kills': 0,
            'deaths': 0,
            'assists': 0,
            'turret_kills': 0,
            'cs': 0,
            'damage': 0,
            'wins': 0,
            'games': 0,
            'wards_placed': 0,
            'gold': 0,
            'atakhan_kills': 0,
            'inhibitor_kills': 0,
            'solo_kills': 0,
            'dragons': 0,
            'barons': 0,
            'vision_score': 0,
            'wards_destroyed': 0,
            'game_time': 0,
            'total_team_kills': 0,
            'kill_participation': 0,
            'average_cs_per_min': 0,
            'vision_score_per_min': 0,
            'kda': 0  # Asegurarse de que esta clave esté presente
        }

    stats = {key: (value if value is not None else 0) for key, value in dict(stats).items()}

    # Calcular total_team_kills (sin filtrar por fecha)
    total_team_kills = query_db("""
        SELECT SUM(kills) as total_team_kills
        FROM player_stats
        WHERE puuid = ? AND champion_id = ?
    """, (puuid, champion_id), one=True)['total_team_kills'] or 0

    stats['total_team_kills'] = total_team_kills
    stats['kill_participation'] = round(((stats['kills'] + stats['assists']) / total_team_kills) * 100, 2) if total_team_kills > 0 else 0

    # Calcular CS por minuto
    stats['average_cs_per_min'] = round((stats['cs'] / (stats['game_time'] / 60)), 2) if stats['game_time'] > 0 else 0

    # Calcular KDA
    stats['kda'] = round((stats['kills'] + stats['assists']) / max(1, stats['deaths']), 2)

    return stats

def calculate_task_progress(task, stats):
    assigned_task_id, task_id, description, objective_type, target_value, points, progress, is_completed, champion, assigned_date = task

    if objective_type == 'kills':
        progress = stats['kills']
    elif objective_type == 'deaths':
        progress = stats['deaths']
    elif objective_type == 'assists':
        progress = stats['assists']
    elif objective_type == 'turret_kills':
        progress = stats['turret_kills']
    elif objective_type == 'cs':
        progress = stats['cs']
    elif objective_type == 'damage':
        progress = stats['damage']
    elif objective_type == 'wins':
        progress = stats['wins']
    elif objective_type == 'games':
        progress = stats['games']
    elif objective_type == 'wards_placed':
        progress = stats['wards_placed']
    elif objective_type == 'gold':
        progress = stats['gold']
    elif objective_type == 'atakhan_kills':
        progress = stats['atakhan_kills']
    elif objective_type == 'inhibitor_kills':
        progress = stats['inhibitor_kills']
    elif objective_type == 'solo_kills':
        progress = stats['solo_kills']
    elif objective_type == 'dragons':
        progress = stats['dragons']
    elif objective_type == 'barons':
        progress = stats['barons']
    elif objective_type == 'kda':
        progress = stats['kda']
    elif objective_type == 'average_cs_per_min':
        progress = stats['average_cs_per_min']
    elif objective_type == 'kill_participation':
        progress = stats.get('kill_participation', 0)
    elif objective_type == 'vision_score':
        progress = stats['vision_score']
    elif objective_type == 'vision_score_per_min':
        progress = stats['vision_score_per_min']
    elif objective_type == 'wards_destroyed':
        progress = stats['wards_destroyed']
    elif objective_type == 'use_specific_champion':
        # Esta lógica puede necesitar ajustes dependiendo de cómo se implemente
        progress = 1 if stats.get('games', 0) > 0 else 0

    return round(progress, 2), is_completed

def store_match_history(puuid):
    match_list_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/by-puuid/{puuid}/ids?start=0&count=20"
    headers = {"X-Riot-Token": API_KEY}
    match_list_response = requests.get(match_list_url, headers=headers)

    if match_list_response.status_code != 200:
        print(f"Error al obtener la lista de partidas para el PUUID {puuid}")
        return

    match_ids = match_list_response.json()
    print(f"Match IDs for PUUID {puuid}: {match_ids}")

    for match_id in match_ids:
        # Verificar si la partida ya existe en la base de datos
        existing_match = query_db("SELECT 1 FROM match_history WHERE match_id = ?", (match_id,), one=True, db='match_history')
        if existing_match:
            print(f"Match {match_id} already exists in the database.")
            continue

        match_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/{match_id}"
        match_response = requests.get(match_url, headers=headers)

        if match_response.status_code != 200:
            print(f"Error al obtener los datos de la partida {match_id}")
            continue

        match_data = match_response.json()
        participants = match_data['info']['participants']
        player_stats = next((p for p in participants if p['puuid'] == puuid), None)

        if not player_stats:
            print(f"No se encontraron estadísticas para el jugador con PUUID {puuid} en la partida {match_id}")
            continue

        match_date = datetime.fromtimestamp(match_data['info']['gameCreation'] / 1000, timezone.utc)
        champion_id = player_stats['championId']
        kills = player_stats['kills']
        deaths = player_stats['deaths']
        assists = player_stats['assists']
        total_gold = player_stats['goldEarned']
        lane = player_stats['teamPosition']
        primary_runes = ','.join([RUNES.get(r['perk'], str(r['perk'])) for r in player_stats['perks']['styles'][0]['selections']])
        secondary_runes = ','.join([RUNES.get(r['perk'], str(r['perk'])) for r in player_stats['perks']['styles'][1]['selections']])
        spells = ','.join([SPELLS.get(player_stats['summoner1Id'], str(player_stats['summoner1Id'])), SPELLS.get(player_stats['summoner2Id'], str(player_stats['summoner2Id']))])
        items = ','.join([str(player_stats[f'item{i}']) for i in range(7) if player_stats[f'item{i}'] != 0])

        # Determinar si el jugador ganó o perdió la partida
        team_id = player_stats['teamId']
        win = any(team['win'] for team in match_data['info']['teams'] if team['teamId'] == team_id)

        # Imprimir estadísticas de la partida en la terminal
        print(f"Match ID: {match_id}")
        print(f"Match Date: {match_date}")
        print(f"Champion ID: {champion_id}")
        print(f"Kills: {kills}, Deaths: {deaths}, Assists: {assists}")
        print(f"Total Gold: {total_gold}")
        print(f"Lane: {lane}")
        print(f"Primary Runes: {primary_runes}")
        print(f"Secondary Runes: {secondary_runes}")
        print(f"Spells: {spells}")
        print(f"Items: {items}")
        print(f"Win: {win}")
        print("-" * 40)

        # Insertar el registro en la base de datos
        try:
            query_db('''
                INSERT INTO match_history (match_id, puuid, match_date, champion_id, kills, deaths, assists, total_gold, lane, primary_runes, secondary_runes, spells, items, win)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (match_id, puuid, match_date, champion_id, kills, deaths, assists, total_gold, lane, primary_runes, secondary_runes, spells, items, win), db='match_history')
            print(f"Match {match_id} inserted into the database.")
        except sqlite3.IntegrityError as e:
            print(f"Error inserting match {match_id} into the database: {e}")
        except sqlite3.OperationalError as e:
            print(f"Database is locked: {e}")
            time.sleep(1)  # Esperar un segundo antes de reintentar
            continue

    # Eliminar las partidas más antiguas si hay más de 20
    try:
        query_db('''
            DELETE FROM match_history
            WHERE match_id NOT IN (
                SELECT match_id
                FROM match_history
                WHERE puuid = ?
                ORDER BY match_date DESC
                LIMIT 20
            )
        ''', (puuid,), db='match_history')
        print(f"Old matches deleted for PUUID {puuid}.")
    except Exception as e:
        print(f"Error deleting old matches for PUUID {puuid}: {e}")

def calculate_champion_stats(puuid):
    headers = {"X-Riot-Token": API_KEY}
    match_ids = []

    # Obtener un total de 20 partidas combinadas entre soloQ y flex
    match_list_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/by-puuid/{puuid}/ids?start=0&count=20"
    match_list_response = requests.get(match_list_url, headers=headers)
    if match_list_response.status_code == 200:
        match_ids.extend(match_list_response.json())
    else:
        print(f"Error al obtener la lista de partidas para el PUUID {puuid}: {match_list_response.status_code} - {match_list_response.text}")

    stats = {}

    for match_id in match_ids:
        # Verificar si la partida ya ha sido procesada
        processed_match = query_db("SELECT 1 FROM processed_matches WHERE match_id = ?", (match_id,), one=True, db='match_history')
        if processed_match:
            continue

        match_url = f"{MATCH_API_BASE_URL}/lol/match/v5/matches/{match_id}"
        success = False
        retries = 0
        while not success and retries < 5:
            match_response = requests.get(match_url, headers=headers)
            if match_response.status_code == 200:
                success = True
            elif match_response.status_code == 429:
                print(f"Rate limit exceeded. Reintentando en 10 segundos...")
                time.sleep(10)
                retries += 1
            else:
                print(f"Error al obtener los datos de la partida {match_id}: {match_response.status_code} - {match_response.text}")
                break

        if not success:
            continue

        match_data = match_response.json()
        participants = match_data['info']['participants']
        player_stats = next((p for p in participants if p['puuid'] == puuid), None)

        if not player_stats:
            print(f"No se encontraron estadísticas para el jugador con PUUID {puuid} en la partida {match_id}")
            continue

        champion_id = player_stats['championId']
        if champion_id not in stats:
            stats[champion_id] = {
                'games_played': 0,
                'total_kills': 0,
                'total_deaths': 0,
                'total_assists': 0,
                'total_wins': 0,
                'total_gold': 0,
                'total_damage': 0
            }

        stats[champion_id]['games_played'] += 1
        stats[champion_id]['total_kills'] += player_stats.get('kills', 0)
        stats[champion_id]['total_deaths'] += player_stats.get('deaths', 0)
        stats[champion_id]['total_assists'] += player_stats.get('assists', 0)
        stats[champion_id]['total_gold'] += player_stats.get('goldEarned', 0)
        stats[champion_id]['total_damage'] += player_stats.get('totalDamageDealtToChampions', 0)
        if player_stats.get('win', False):
            stats[champion_id]['total_wins'] += 1

        # Marcar la partida como procesada
        query_db("INSERT INTO processed_matches (match_id) VALUES (?)", (match_id,), db='match_history')

    # Guardar los datos en la base de datos match_history.db
    for champion_id, champ_stats in stats.items():
        query_db('''
            INSERT OR REPLACE INTO champion_stats (puuid, champion_id, games_played, total_kills, total_deaths, total_assists, total_wins, total_gold, total_damage)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (puuid, champion_id, champ_stats['games_played'], champ_stats['total_kills'], champ_stats['total_deaths'], champ_stats['total_assists'], champ_stats['total_wins'], champ_stats['total_gold'], champ_stats['total_damage']), db='match_history')

    for champ_stats in stats.values():
        champ_stats['kda'] = round((champ_stats['total_kills'] + champ_stats['total_assists']) / max(1, champ_stats['total_deaths']), 2)
        champ_stats['win_ratio'] = round((champ_stats['total_wins'] / champ_stats['games_played']) * 100, 2) if champ_stats['games_played'] > 0 else 0

    return stats

# Endpoint para actualizar el progreso de las tareas
@app.route('/update-progress', methods=['POST', 'GET'])
@login_required
@admin_required
def update_progress():
    if request.method == 'POST':
        summoner_name = request.form.get('summoner_name')

        player = query_db("SELECT puuid, last_update FROM players WHERE summoner_name = ?", (summoner_name,), one=True)
        if not player:
            flash("Jugador no encontrado")
            return redirect(url_for('update_progress'))

        puuid, last_update = player

        # Obtener estadísticas del jugador una sola vez
        player_stats = get_player_stats(puuid, last_update)
        champion_stats = {}

        assigned_tasks = query_db("""
            SELECT at.id, t.id, t.description, t.objective_type, t.target_value, t.points, at.progress, at.is_completed, t.champion, at.assigned_date 
            FROM assigned_tasks at 
            JOIN tasks t ON at.task_id = t.id 
            WHERE at.player_id = (SELECT id FROM players WHERE summoner_name = ?) 
            AND at.is_completed = 0
        """, (summoner_name,))
        
        updated_tasks = []
        for task in assigned_tasks:
            if task[8]:  # Si la tarea tiene un campeón específico
                if task[8] not in champion_stats:
                    champion_stats[task[8]] = get_champion_stats(puuid, task[8])  # Eliminado last_update
                stats = champion_stats[task[8]]
            else:
                stats = player_stats

            progress, is_completed = calculate_task_progress(task, stats)

            # No acumular el progreso existente si no es necesario
            new_progress = progress

            if new_progress >= float(task[4]):
                is_completed = True
                query_db("UPDATE players SET points = points + ? WHERE id = (SELECT id FROM players WHERE summoner_name = ?)", (task[5], summoner_name))

            query_db("UPDATE assigned_tasks SET progress = ?, is_completed = ? WHERE id = ?", (round(new_progress, 2), is_completed, task[0]))
            updated_tasks.append({
                "description": task[2],
                "progress": round(new_progress, 2),
                "is_completed": bool(is_completed),
                "target_value": float(task[4]),
                "kill_participation": stats.get('kill_participation', 0)
            })

        query_db("UPDATE players SET last_update = CURRENT_TIMESTAMP WHERE puuid = ?", (puuid,))

        flash("Progreso actualizado")
        return render_template('update_progress.html', updated_tasks=updated_tasks)

    return render_template('update_progress.html')

@app.route('/players-tasks', methods=['GET'])
@login_required
def get_players_tasks():
    if current_user.role == 'admin':
        players_tasks = query_db("""
            SELECT p.id as player_id, p.summoner_name, t.id as task_id, t.description, at.progress, at.is_completed, t.target_value
            FROM players p
            JOIN assigned_tasks at ON p.id = at.player_id
            JOIN tasks t ON at.task_id = t.id
        """)
    else:
        players_tasks = query_db("""
            SELECT p.id as player_id, p.summoner_name, t.id as task_id, t.description, at.progress, at.is_completed, t.target_value
            FROM players p
            JOIN assigned_tasks at ON p.id = at.player_id
            JOIN tasks t ON at.task_id = t.id
            WHERE p.puuid = ? OR p.summoner_name = ?
        """, (current_user.puuid, current_user.summoner_name))

    result = {}
    for player_task in players_tasks:
        player_id, summoner_name, task_id, description, progress, is_completed, target_value = player_task
        if summoner_name not in result:
            result[summoner_name] = []
        result[summoner_name].append({
            "player_id": player_id,
            "id": task_id,
            "description": description,
            "progress": round(progress, 2),  # Redondear y convertir a entero
            "is_completed": bool(is_completed),
            "target_value": float(target_value)
        })

    return render_template('players_tasks.html', players_tasks=result)

@app.route('/update-user', methods=['GET', 'POST'])
@login_required
@admin_required
def update_user():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        puuid = request.form.get('puuid')
        summoner_name = request.form.get('summoner_name')

        query_db(
            "UPDATE users SET puuid = ?, summoner_name = ? WHERE id = ?",
            (puuid, summoner_name, user_id)
        )
        flash('Usuario actualizado correctamente.')
        return redirect(url_for('admin_dashboard'))

    user_id = request.args.get('user_id')
    users = query_db("SELECT id, username FROM users ORDER BY username")
    players = query_db("SELECT puuid, summoner_name FROM players ORDER BY summoner_name")

    user = None
    if user_id:
        user = query_db("SELECT id, username, puuid, summoner_name FROM users WHERE id = ?", (user_id,), one=True)
    
    if not user:
        user = {
            'id': '',
            'username': '',
            'puuid': '',
            'summoner_name': ''
        }

    return render_template('update_user.html', users=users, players=players, user=user, user_id=user_id)

# Ruta para desasignar una tarea
@app.route('/unassign-task', methods=['POST'])
@login_required
@admin_required
def unassign_task():
    task_id = request.form.get('task_id')
    player_id = request.form.get('player_id')

    if not task_id or not player_id:
        flash("Faltan datos para desasignar la tarea.")
        return redirect(url_for('get_players_tasks'))

    query_db("DELETE FROM assigned_tasks WHERE task_id = ? AND player_id = ?", (task_id, player_id))
    flash("Tarea desasignada con éxito.")
    return redirect(url_for('get_players_tasks'))

@app.route('/players-champs', methods=['GET'])
@login_required
def get_players_champs():
    # Obtener jugadores de league_tasks.db
    players = query_db("SELECT summoner_name, profile_icon_id, puuid FROM players", db='league_tasks')

    result = {}
    for player in players:
        summoner_name = player['summoner_name']
        profile_icon_id = player['profile_icon_id']
        puuid = player['puuid']

        # Inicializar la estructura de datos para cada jugador
        result[summoner_name] = {
            "profile_icon_id": profile_icon_id,
            "puuid": puuid,
            "total_games": 0,
            "total_wins": 0,
            "champs": []
        }

        # Obtener estadísticas de los campeones de match_history.db
        player_champs = query_db("""
            SELECT champion_id, games_played, total_kills, total_deaths, total_assists, total_gold, total_damage, total_wins
            FROM champion_stats
            WHERE puuid = ?
        """, (puuid,), db='match_history')

        for champ_stats in player_champs:
            champion_id = champ_stats['champion_id']
            champion_name = champions.get(champion_id, "Unknown Champion")
            games_played = champ_stats['games_played']
            total_kills = champ_stats['total_kills']
            total_deaths = champ_stats['total_deaths']
            total_assists = champ_stats['total_assists']
            total_gold = champ_stats['total_gold']
            total_damage = champ_stats['total_damage']
            total_wins = champ_stats['total_wins']

            result[summoner_name]["total_games"] += games_played
            result[summoner_name]["total_wins"] += total_wins

            champ_stats = {
                "games_played": games_played,
                "total_kills": total_kills,
                "total_deaths": total_deaths,
                "total_assists": total_assists,
                "kda": round((total_kills + total_assists) / max(1, total_deaths), 2),
                "win_ratio": round((total_wins / games_played) * 100, 2) if games_played > 0 else 0,
                "total_gold": total_gold,
                "total_damage": total_damage
            }

            result[summoner_name]["champs"].append({
                "champion_id": champion_id,
                "champion_name": champion_name,
                **champ_stats
            })

        # Ordenar los campeones por juegos jugados y tomar los 6 primeros
        result[summoner_name]["champs"] = sorted(result[summoner_name]["champs"], key=lambda x: x['games_played'], reverse=True)[:6]

    return render_template('players_champs.html', players_champs=result)

@app.route('/update-champion-stats/<puuid>', methods=['POST'])
@login_required
@admin_required
def update_champion_stats(puuid):
    stats = calculate_champion_stats(puuid)

    if not stats:
        flash("No se pudieron obtener las estadísticas del jugador.")
        return redirect(url_for('get_players_champs'))

    player = query_db("SELECT summoner_name, profile_icon_id FROM players WHERE puuid = ?", (puuid,), one=True, db='league_tasks')
    if not player:
        flash("Jugador no encontrado.")
        return redirect(url_for('get_players_champs'))

    summoner_name = player['summoner_name']
    profile_icon_id = player['profile_icon_id']

    result = {
        summoner_name: {
            "profile_icon_id": profile_icon_id,
            "total_games": sum(champ['games_played'] for champ in stats.values()),
            "total_wins": sum(champ['total_wins'] for champ in stats.values()),
            "champs": []
        }
    }

    for champion_id, champ_stats in stats.items():
        champ_stats['champion_id'] = champion_id
        champ_stats['champion_name'] = champions.get(champion_id, "Unknown Champion")
        result[summoner_name]["champs"].append(champ_stats)

    # Ordenar los campeones por juegos jugados y tomar los 6 primeros
    result[summoner_name]["champs"] = sorted(result[summoner_name]["champs"], key=lambda x: x['games_played'], reverse=True)[:6]

    flash(f"Estadísticas de {summoner_name} actualizadas con éxito.")
    return redirect(url_for('get_players_champs'))

@app.route('/match-history', methods=['GET', 'POST'])
@login_required
def match_history():
    if request.method == 'POST':
        summoner_name = request.form.get('summoner_name')
    else:
        summoner_name = request.args.get('summoner_name')

    players = query_db("SELECT summoner_name FROM players", db='league_tasks')

    if not summoner_name:
        return render_template('match_history.html', players=players, matches=[])

    player = query_db("SELECT puuid FROM players WHERE summoner_name = ?", (summoner_name,), one=True, db='league_tasks')
    if not player:
        flash("Jugador no encontrado")
        return redirect(url_for('match_history'))

    puuid = player['puuid']

    # Obtener el elo del jugador
    summoner_id = get_summoner_id(summoner_name)
    elo = get_soloq_elo(summoner_id) if summoner_id else "Sin ranking"

    # Llamar a store_match_history para actualizar el historial de partidas
    store_match_history(puuid)

    matches = query_db("SELECT match_date, champion_id, kills, deaths, assists, total_gold, lane, primary_runes, secondary_runes, spells, items, win FROM match_history WHERE puuid = ? ORDER BY match_date DESC LIMIT 20", (puuid,), db='match_history')

    match_data = []
    for match in matches:
        spells = match['spells']
        spell1, spell2 = spells.split(',') if isinstance(spells, str) else ("unknown", "unknown")

        items = match['items']
        items = str(items) if not isinstance(items, str) else items

        champion_name = champions.get(match['champion_id'], "Unknown Champion")

        item_ids = [str(int(item)) if item.isdigit() else item for item in items.split(',')]

        primary_rune_ids = match['primary_runes'].split(',')
        secondary_rune_ids = match['secondary_runes'].split(',')

        match_data.append({
            "match_date": match['match_date'],
            "champion_id": str(match['champion_id']),
            "champion_name": champion_name,
            "kills": match['kills'],
            "deaths": match['deaths'],
            "assists": match['assists'],
            "total_gold": match['total_gold'],
            "lane": match['lane'],
            "primary_runes": primary_rune_ids,
            "secondary_runes": secondary_rune_ids,
            "spells": spells,
            "item_list": ','.join(item_ids),
            "elo": elo,  # Se agrega el ELO real del jugador
            "spell1_icon": f"{spell1}.png",
            "spell2_icon": f"{spell2}.png",
            "result": "Win" if match['win'] else "Loss"
        })

    print(f"Match data for {summoner_name}: {match_data}")  # Debugging

    return render_template('match_history.html', players=players, matches=match_data)


def get_summoner_id(summoner_name):
    """ Obtiene el ID del invocador desde la base de datos league_tasks.db y luego desde la Riot API. """
    # Obtener el PUUID del jugador desde la base de datos
    player = query_db("SELECT puuid FROM players WHERE summoner_name = ?", (summoner_name,), one=True, db='league_tasks')
    if not player:
        print(f"Jugador con nombre {summoner_name} no encontrado en la base de datos.")
        return None

    puuid = player['puuid']

    # Hacer una solicitud a la API de Riot para obtener el ID del invocador usando el PUUID
    url = f"{SUMMONER_API_BASE_URL}/lol/summoner/v4/summoners/by-puuid/{puuid}?api_key={API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get("id")
    else:
        print(f"Error en la API: {response.status_code}, {response.text}")
        return None


def get_soloq_elo(summoner_id):
    """ Obtiene el ELO del jugador en SoloQ, o Flex si no tiene SoloQ. """
    if not summoner_id:
        print("Error: summoner_id es None.")
        return "Sin ranking"

    url = f"{SUMMONER_API_BASE_URL}/lol/league/v4/entries/by-summoner/{summoner_id}?api_key={API_KEY}"
    response = requests.get(url)

    if response.status_code != 200:
        print(f"Error en la API: {response.status_code}, {response.text}")
        return "Error obteniendo ranking"

    rank_data = response.json()

    # Verificar si tiene SoloQ
    for queue in rank_data:
        if queue["queueType"] == "RANKED_SOLO_5x5":
            return f"{queue['tier']} {queue['rank']} ({queue['leaguePoints']} LP)"

    # Si no tiene SoloQ, verificar Flex
    for queue in rank_data:
        if queue["queueType"] == "RANKED_FLEX_SR":
            return f"Flex {queue['tier']} {queue['rank']} ({queue['leaguePoints']} LP)"

    return "Sin ranking"

# Inicializar la base de datos y correr la app
if __name__ == '__main__':
    init_league_tasks_db()
    init_match_history_db()
    app.run(debug=True)
