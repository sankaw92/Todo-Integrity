from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify
from flask import request
from flask_jwt_extended import JWTManager, create_access_token
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://nhjjvqnk:8J81LoaioKM1yfTgVX-p563UQeEPQHg1@motty.db.elephantsql.com/nhjjvqnk'
db = SQLAlchemy(app)
jwt = JWTManager(app)

class Todo(db.Model):
    __tablename__ = 'todos'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    updated_timestamp = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(255), nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    updated_timestamp = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    todos = db.relationship('Todo', backref='user', lazy=True)

    @app.route('/api/v1/signup', methods=['POST'])
    def signup():
        email = request.json['email']
        password = request.json['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201

    @app.route('/api/v1/signin', methods=['POST'])
    def signin():
        email = request.json['email']
        password = request.json['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            access_token = create_access_token(identity=user.id)
            user.jwt_token = access_token
            db.session.commit()

            return jsonify({'access_token': access_token}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    @app.route('/api/v1/changePassword', methods=['PUT'])
    @jwt_required
    def change_password():
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if user:
            new_password = request.json['password']
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password
            db.session.commit()
            return jsonify({'message': 'Password updated successfully'}), 200
        else:
            return jsonify({'message': 'Unauthorized'}), 401

    @app.route('/api/v1/todos')
    @jwt_required
    def get_todos():
        status = request.args.get('status')

        if status:
            todos = Todo.query.filter_by(status=status).all()
        else:
            todos = Todo.query.all()

        todos_list = []
        for todo in todos:
            todos_list.append({
                'id': todo.id,
                'status': todo.status,
                'description': todo.description
            }

        return jsonify({'todos': todos_list}), 200

    @app.route('/api/v1/todos', methods=['POST'])
    @jwt_required
    def create_todo():
        current_user = get_jwt_identity()
        status = request.json['status']
        description = request.json['description']

        new_todo = Todo(status=status, description=description, user_id=current_user)
        db.session.add(new_todo)
        db.session.commit()

        return jsonify({'message': 'Todo created successfully'}), 201

    @app.route('/api/v1/todos/<int:todo_id>', methods=['PUT'])
    @jwt_required
    def update_todo(todo_id):
        current_user = get_jwt_identity()
        todo = Todo.query.filter_by(id=todo_id, user_id=current_user).first()
        if todo:
            if 'status' in request.json:
                todo.status = request.json['status']
            if 'description' in request.json:
                todo.description = request.json['description']
            db.session.commit()
            return jsonify({'message': 'Todo updated successfully'}), 200
        else:
            return jsonify({'message': 'Unauthorized'}), 401

    @app.route('/api/v1/todos/<int:todo_id>', methods=['DELETE'])
    @jwt_required
    def delete_todo(todo_id):
        current_user = get_jwt_identity()
        todo = Todo.query.filter_by(id=todo_id, user_id=current_user).first()
        if todo:
            db.session.delete(todo)
            db.session.commit()
            return jsonify({'message': 'Todo deleted successfully'}), 200
        else:
            return jsonify({'message': 'Unauthorized'}), 401