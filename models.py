import sqlite3
from Crypto.PublicKey import RSA

def init_db():
    conn = sqlite3.connect('encryption.db')
    cursor = conn.cursor()
    
    # 创建用户表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')
    
    # 创建密钥对表
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
