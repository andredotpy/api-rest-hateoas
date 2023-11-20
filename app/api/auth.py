import functools

from flask import (
    Blueprint,
    g,
    redirect,
    request,
    session,
    url_for,
    Response,
)
from http import HTTPStatus
from werkzeug.security import check_password_hash, generate_password_hash

from ..model.db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/register", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        db = get_db()

        if not username or not password:
            return Response(
                response="Username and Password are required.",
                status=HTTPStatus.BAD_REQUEST,
            )

        try:
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except db.IntegrityError:
            return Response(
                response=f"User {username} is already registered.",
                status=HTTPStatus.BAD_REQUEST,
            )
    return Response(
        response=f"User {username} successfully registered.", status=HTTPStatus.CREATED
    )


@bp.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        db = get_db()

        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password"], password):
            return Response(
                response="Incorrect username or password.",
                status=HTTPStatus.UNPROCESSABLE_ENTITY,
            )

        session.clear()
        session["user_id"] = user["id"]

    return Response(
        response=f"User {username} successfully logged in", status=HTTPStatus.OK
    )


@bp.route("/logout")
def logout():
    username = request.json.get("username", None)
    if not username:
        return Response(
            response="Username is required.",
            status=HTTPStatus.BAD_REQUEST,
        )

    session.clear()
    return Response(
        response=f"User {username} successfully logged out", status=HTTPStatus.OK
    )


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return Response(response="Login required.", status=HTTPStatus.UNAUTHORIZED)

        return view(**kwargs)

    return wrapped_view
