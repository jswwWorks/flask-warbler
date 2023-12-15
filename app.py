import os
from dotenv import load_dotenv

from flask import Flask, render_template, request, flash, redirect, session, g
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

from forms import (
    UserAddForm,
    LoginForm,
    MessageForm,
    CSRFProtectForm,
    EditProfileForm
    )
from models import (
    db,
    connect_db,
    User,
    Message,
    Follow,
    Like,
    DEFAULT_IMAGE_URL,
    DEFAULT_HEADER_IMAGE_URL
    )

load_dotenv()

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
toolbar = DebugToolbarExtension(app)

connect_db(app)


##############################################################################
# Form protection

@app.before_request
def add_csrf_to_g():
    """Before each request, add CSRF protection to any form."""

    g.csrf_form = CSRFProtectForm()


##############################################################################
# User signup/login/logout

@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Log out user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    do_logout()

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken or email already used", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect("/")

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login and redirect to homepage on success."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(
            form.username.data,
            form.password.data,
        )

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.post('/logout')
def logout():
    """Handle logout of user and redirect to homepage."""

    form = g.csrf_form

    if form.validate_on_submit() and g.user:

        do_logout()
        flash("You have sucessfully logged out. Come again soon!")
        return redirect("/login")

    #can add a flash message for unauthorization
    return redirect("/")


##############################################################################
# General user routes:

@app.get('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.get('/users/<int:user_id>')
def show_user(user_id):
    """Show user profile."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)

    return render_template('users/show.html', user=user)


@app.get('/users/<int:user_id>/following')
def show_following(user_id):
    """Show list of people this user is following."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)


@app.get('/users/<int:user_id>/followers')
def show_followers(user_id):
    """Show list of followers of this user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)


@app.post('/users/follow/<int:follow_id>')
def start_following(follow_id):
    """Add a follow for the currently-logged-in user.

    Redirect to following page for the current for the current user.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = g.csrf_form

    if form.validate_on_submit():
        followed_user = User.query.get_or_404(follow_id)
        g.user.following.append(followed_user)
        db.session.commit()

        return redirect(f"/users/{g.user.id}/following")

    # Redirects to homepage if CSRF token isn't present
    return redirect("/")




@app.post('/users/stop-following/<int:follow_id>')
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user.

    Redirect to following page for the current for the current user.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = g.csrf_form

    if form.validate_on_submit():
        followed_user = User.query.get_or_404(follow_id)
        g.user.following.remove(followed_user)
        db.session.commit()

        return redirect(f"/users/{g.user.id}/following")



    # Redirects to homepage if CSRF token isn't present
    return redirect("/")



@app.route('/users/profile', methods=["GET", "POST"])
def edit_profile():
    """Update profile for current user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = EditProfileForm(obj=g.user)

    #handle default image displaying when nothing is entered to url box
    #sql alch doesn't handle default image displaying when updating only on creation
    if form.validate_on_submit():

        user = g.user
        password = form.password.data
        original_username = user.username

        user = User.authenticate(
            username=original_username,
            password=password
        )

        if not user:
            form.username.errors = ["Invalid password. Please try again."]

        else:
            # If validation succeeds, grab information to update page
            user.username = form.username.data
            user.email = form.email.data
            user.image_url = form.image_url.data or DEFAULT_IMAGE_URL
            # user.image_url = form.image_url.data
            user.header_image_url = form.header_image_url.data or DEFAULT_HEADER_IMAGE_URL
            user.bio = form.bio.data

            # if not user.image_url:
            #     user.image_url = DEFAULT_IMAGE_URL

            # if not user.header_image_url:
            #     user.header_image_url = DEFAULT_HEADER_IMAGE_URL

            #can remove db.session.add(user)
            db.session.add(user)
            db.session.commit()
            return redirect(f"/users/{user.id}")

    return render_template("/users/edit.html", form=form)



@app.post('/users/delete')
def delete_user():
    """Delete user.

    Redirect to signup page.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")


    form = g.csrf_form

    if form.validate_on_submit():
        try:
            Message.query.filter(g.user.id == Message.user_id).delete()
            Follow.query.filter(
                db.or_(g.user.id == Follow.user_being_followed_id,
                       g.user.id == Follow.user_following_id)
                       ).delete()

        except IntegrityError:
            flash("Error: Cannot delete user!")
            return redirect(f"/users/{g.user.id}")

        do_logout()

        db.session.delete(g.user)
        db.session.commit()

        return redirect("/signup")
    #can flash message about malicious no csrf token actions
    return redirect("/")


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
def add_message():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return render_template('messages/create.html', form=form)


@app.get('/messages/<int:message_id>')
def show_message(message_id):
    """Show a message."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    msg = Message.query.get_or_404(message_id)
    return render_template('messages/show.html', message=msg)


@app.post('/messages/<int:message_id>/delete')
def delete_message(message_id):
    """Delete a message.

    Check that this message was written by the current user.
    Redirect to user page on success.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = g.csrf_form

    if form.validate_on_submit():
        msg = Message.query.get_or_404(message_id)
        # Ensures users can only delete their own messages
        if msg.user_id == g.user.id:
            print(msg.user_id, "=msg.user_id", g.user.id, "=g.user.id")
            db.session.delete(msg)
            db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return redirect("/")


# FIXME: should this be a patch request? ask
# TODO: maybe decompose this to a helper function in the future?
@app.post('/messages/<int:message_id>/alter_like_state')
def alter_like_state(message_id):
    """Takes message_id (an integer).

    Lets logged in users like/unlike the given message. (If user had previously
    liked a message, then this would unlike it, and vice versa).

    Re-renders template with like field.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = g.csrf_form

    if form.validate_on_submit():

        msg = Message.query.get_or_404(message_id)
        user = g.user

        if msg.user_id == g.user.id:
            flash("you cannot like/ unlike your own message!")
            return redirect(f"/users/{g.user.id}")

        like_query = Like.query.filter(
            db.and_(Like.user_id == user.id,
                    Like.message_id == msg.id))

        like = like_query.one_or_none()

        # We're looking in the likes table to see if there is a row
        # where the id of the user is equal to the currently logged in user
        # AND where the id of the message is equal to the id of the liked message

        if like:
            like_query.delete()
            db.session.commit()
            flash("you have unliked this message")

        else:
            new_like = Like(user_id=g.user.id, message_id=message_id)
            db.session.add(new_like)
            db.session.commit()
            flash("you liked the message! thanks so much!")

        return redirect(f"/users/{g.user.id}")

    flash("Access unauthorized.", "danger")
    return redirect('/')
#     Overall steps in process:

#      - update html to include a field (potentially using icons from bootstrap)

#     2 steps to accomplishing this:
#     option 1) have 2 images that we're swapping between
#     option 2) we have a class "liked" and a class "unliked" where everything
# has a preset state of being unliked. When the class turns to liked, then in the
# # css it knows to swap the images.

# figuring out routing (the icon should be a button within a form that has
# csrf protection and the form's action is this route.)

# as for actually liking/unliking, to separate concerns it might make the most
# sense to have a helper funciton that swaps classes its own thing


# in this view function: it would add/ remove the liked row to/from the model.






##############################################################################
# Homepage and error pages


@app.get('/')
def homepage():
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of self & followed_users
    """

    if g.user:

        users_list = g.user.following
        #could make into list comprehension
        following_ids = []

        for item in users_list:
            following_ids.append(item.id)

        messages = (Message
                    .query
                    .filter(
                        db.or_(Message.user_id == g.user.id,
                        Message.user_id.in_(following_ids))
                    )
                    .order_by(Message.timestamp.desc())
                    .limit(100)
                    .all())

        return render_template('home.html', messages=messages)

    else:
        return render_template('home-anon.html')


@app.after_request
def add_header(response):
    """Add non-caching headers on every request."""

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
    response.cache_control.no_store = True
    return response
