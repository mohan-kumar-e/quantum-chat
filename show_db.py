import sqlite3

def show_database():
    print("\n" + "="*80)
    print(" QUANTUM ENCRYPTED DATABASE: chat.db")
    print("=" * 80)
    
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT sender, receiver, message FROM messages")
        rows = cursor.fetchall()
        
        if not rows:
            print(" The messages table is currently empty. Start chatting first!")
        
        for idx, row in enumerate(rows):
            sender, receiver, msg = row
            print(f"\n--- MESSAGE {idx+1} ---")
            print(f"From: {sender}")
            print(f"To:   {receiver}")
            print(f"Encrypted Payload:\n{msg[:150]}...[TRUNCATED FOR DISPLAY]")
            
    except sqlite3.OperationalError:
        print(" Error: The database or 'messages' table does not exist yet.")
        
    print("\n" + "="*80 + "\n")
    conn.close()

if __name__ == "__main__":
    show_database()
