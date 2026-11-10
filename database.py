import sqlite3

DB_NAME = "chat.db"

def connect():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = connect()
    cursor = conn.cursor()

    # USERS table with new public_key field for PQC
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            public_key TEXT,
            last_seen TEXT
        )
    """)

    # MESSAGES table (will store base64 encrypted ciphertexts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            message TEXT,
            timestamp TEXT,
            is_read INTEGER DEFAULT 0
        )
    """)

    # Check if columns exist (for upgrading old DBs)
    try:
        cursor.execute("SELECT public_key FROM users LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
        
    try:
        cursor.execute("SELECT last_seen FROM users LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
        
    try:
        cursor.execute("SELECT is_read FROM messages LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0")

    conn.commit()
    conn.close()


def register_user(username, password, public_key_hex):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)",
            (username, password, public_key_hex)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def login_user(username, password):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None


def get_public_key(username):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT public_key FROM users WHERE username=?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def get_contacts(username):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, last_seen FROM users WHERE username!=?",
        (username,)
    )
    users = [{"username": row[0], "last_seen": row[1]} for row in cursor.fetchall()]
    conn.close()
    return users

def update_last_seen(username, time_str):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET last_seen=? WHERE username=?", (time_str, username))
    conn.commit()
    conn.close()


def save_message(sender, receiver, msg, time):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages
        (sender, receiver, message, timestamp, is_read)
        VALUES (?, ?, ?, ?, 0)
    """, (sender, receiver, msg, time))
    conn.commit()
    conn.close()


def get_private_messages(sender, receiver):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, receiver, message, timestamp, is_read
        FROM messages
        WHERE (sender=? AND receiver=?)
        OR (sender=? AND receiver=?)
        ORDER BY id
    """, (sender, receiver, receiver, sender))
    
    data = cursor.fetchall()
    # Format data for python logic
    formatted_data = []
    for row in data:
        formatted_data.append({
            "sender": row[0],
            "receiver": row[1],
            "packed_message": row[2],
            "time": row[3],
            "is_read": bool(row[4])
        })
    conn.close()
    return formatted_data

def mark_messages_read(sender, receiver):
    conn = connect()
    cursor = conn.cursor()
    # Mark messages sent by the 'sender' to the 'receiver' as read.
    # Note: 'sender' here refers to the original sender. The person marking them as read is the DB receiver.
    cursor.execute("""
        UPDATE messages SET is_read=1
        WHERE sender=? AND receiver=? AND is_read=0
    """, (sender, receiver))
    conn.commit()
    conn.close()
