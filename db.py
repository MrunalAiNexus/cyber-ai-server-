# db.py
import oracledb

conn = oracledb.connect(
    user="system",
    password="mrunal",         # your password
    dsn="localhost:1521/xe"   # correct SID/service name
)

cursor = conn.cursor()
print("✅ Oracle Database Connected Successfully")
