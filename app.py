from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/')
def home():
    return "Welcome to the Flask Demo App!"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Example: Only one valid login
    if username == "admin" and password == "secure123":
        app.logger.info(f"SUCCESSFUL LOGIN: {username}")
        return jsonify({"message": "Login successful!"}), 200
    else:
        app.logger.warning(f"FAILED LOGIN: {username}")
        return jsonify({"message": "FAILED LOGIN"}), 401

if __name__ == '__main__':
    app.run(debug=True)
