from flask import Flask, send_from_directory, jsonify, request, make_response, Response  # 添加Response
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__, static_folder='static')
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 生产环境应更改为随机字符串


# 数据库初始化
def init_db():
    conn = sqlite3.connect('encryption.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS key_pairs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        private_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect('encryption.db')
    conn.row_factory = sqlite3.Row
    return conn


# 初始化数据库
init_db()


# 认证装饰器
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            conn = get_db_connection()
            current_user = conn.execute('SELECT * FROM users WHERE id = ?', (data['user_id'],)).fetchone()
            conn.close()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/api/test_db', methods=['GET'])
def test_db():
    try:
        conn = get_db_connection()
        conn.execute("SELECT 1")
        conn.close()
        return jsonify({"status": "Database connection OK"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 静态文件路由
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_file(path):
    return send_from_directory(app.static_folder, path)


# API路由
@app.route('/api/register', methods=['POST'])
def register():
    try:
        if not request.is_json:
            return jsonify({"message": "Request must be JSON"}), 400

        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        app.logger.info(f'Registration attempt for: {username}')

        if not username or not password:
            return jsonify({'message': 'Username and password are required!'}), 400

        conn = None
        try:
            conn = get_db_connection()
            user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

            if user:
                return jsonify({'message': 'User already exists!'}), 400

            # 使用正确的哈希方法
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                           (username, hashed_password))
            user_id = cursor.lastrowid

            # 生成RSA密钥对
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            cursor.execute('INSERT INTO key_pairs (user_id, public_key, private_key) VALUES (?, ?, ?)',
                           (user_id, public_key.decode('utf-8'), private_key.decode('utf-8')))

            conn.commit()

            return jsonify({
                'message': 'User registered successfully!',
                'username': username
            }), 201

        except sqlite3.Error as e:
            app.logger.error(f'Database error: {str(e)}')
            if conn:
                conn.rollback()
            return jsonify({'message': 'Database operation failed', 'error': str(e)}), 500

        finally:
            if conn:
                conn.close()

    except Exception as e:
        app.logger.error(f'Unexpected error: {str(e)}')
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    auth = request.get_json()
    username = auth.get('username')
    password = auth.get('password')

    if not username or not password:
        return jsonify({'message': '用户名和密码必须填写！'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'message': '用户名或密码错误！'}), 401

    try:
        token = jwt.encode(
            payload={
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            },
            key=app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        
        # 确保token是字符串类型
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({
            'token': token,
            'username': user['username']
        })

    except Exception as e:
        app.logger.error(f'JWT生成失败: {str(e)}')
        return jsonify({'message': '服务器错误'}), 500
# 图片加密（返回Base64字符串）
@app.route('/api/encrypt_image', methods=['POST'])
@token_required
def encrypt_image(current_user):
    if 'file' not in request.files:
        return jsonify({'message': '未上传文件'}), 400
    
    recipient = request.form.get('recipient')
    file = request.files['file']
    
     if file.filename == '':
        return jsonify({'message': '未选择文件'}), 400
    
    # 生成随机密钥和初始化向量
    key = os.urandom(32)  # AES-256
    iv = os.urandom(16)
    
    # 创建加密器
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # 读取并加密图片
    image_data = file.read()
    encrypted_data = cipher.encrypt(pad(image_data, AES.block_size))
    
    return jsonify({
        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
        'recipient': recipient
    })

# 图片解密
@app.route('/api/decrypt_image', methods=['POST'])
@token_required
def decrypt_image(current_user):
    data = request.get_json()
    encrypted_data = base64.b64decode(data['encrypted_data'])
    
    try:
        # 解码数据
        encrypted_data = base64.b64decode(data['encrypted_data'])
        key = base64.b64decode(data['key'])
        iv = base64.b64decode(data['iv'])
        
        # 创建解密器
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # 解密数据
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        # 返回解密后的图片数据
        return Response(
            decrypted_data,
            mimetype='application/octet-stream',
            headers={'Content-Disposition': 'attachment;filename=decrypted_image.png'}
        )
    except Exception as e:
        return jsonify({
        'decrypted_data': base64.b64encode(decrypted_data).decode('utf-8'),
        'mime_type': 'image/png'  # 自动检测图片类型更佳
    })

@app.route('/api/keys', methods=['GET'])
@token_required
def get_keys(current_user):
    conn = get_db_connection()
    key_pair = conn.execute('''
        SELECT public_key 
        FROM key_pairs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    ''', (current_user['id'],)).fetchone()
    conn.close()

    if not key_pair:
        return jsonify({'message': 'No key pair found!'}), 404

    return jsonify({
        'public_key': key_pair['public_key']
    })


@app.route('/api/encrypt', methods=['POST'])
@token_required
def encrypt_message(current_user):
    data = request.get_json()
    recipient_username = data.get('recipient')
    message = data.get('message')

    if not recipient_username or not message:
        return jsonify({'message': 'Recipient and message are required!'}), 400

    conn = get_db_connection()
    recipient = conn.execute('SELECT id FROM users WHERE username = ?', (recipient_username,)).fetchone()

    if not recipient:
        conn.close()
        return jsonify({'message': 'Recipient not found!'}), 404

    key_pair = conn.execute('''
        SELECT public_key 
        FROM key_pairs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    ''', (recipient['id'],)).fetchone()
    conn.close()

    if not key_pair:
        return jsonify({'message': 'Recipient has no public key!'}), 404

    # 加密消息
    public_key = RSA.import_key(key_pair['public_key'])
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode('utf-8'))
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')

    return jsonify({
        'encrypted_message': encrypted_b64,
        'recipient': recipient_username
    })


@app.route('/api/decrypt', methods=['POST'])
@token_required
def decrypt_message(current_user):
    data = request.get_json()
    encrypted_b64 = data.get('encrypted_message')

    if not encrypted_b64:
        return jsonify({'message': 'Encrypted message is required!'}), 400

    conn = get_db_connection()
    key_pair = conn.execute('''
        SELECT private_key 
        FROM key_pairs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    ''', (current_user['id'],)).fetchone()
    conn.close()

    if not key_pair:
        return jsonify({'message': 'No private key found!'}), 404

    # 解密消息
    private_key = RSA.import_key(key_pair['private_key'])
    cipher = PKCS1_OAEP.new(private_key)

    try:
        encrypted = base64.b64decode(encrypted_b64)
        decrypted = cipher.decrypt(encrypted).decode('utf-8')
    except Exception as e:
        return jsonify({'message': 'Decryption failed!', 'error': str(e)}), 400

    return jsonify({
        'decrypted_message': decrypted
    })


if __name__ == '__main__':
    # 确保静态文件夹存在
    if not os.path.exists(app.static_folder):
        os.makedirs(app.static_folder)

    app.run(debug=True, port=5000)
