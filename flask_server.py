from flask import Flask, render_template, flash
from flask import redirect, request, url_for, jsonify
from database_setup import *
from database_helper import *

from flask import session
import random
import string
from functools import wraps

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# decorators start


def user_logged_in(function):

    @wraps(function)
    def wrapper(*args, **kwargs):
        if 'logged_in' in session:
            return function(*args, **kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return wrapper


def can_edit_category(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        category_id = kwargs.get('category_id')
        category = get_category_by_id(category_id)

        if category and session['user_id'] == category.created_by_id:
            return function(*args, **kwargs)
        else:
            flash('You are not authorized to access this resource')
            return redirect(url_for('showCatalog'))
    return wrapper


def can_edit_category_item(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        category_item_id = kwargs.get('category_item_id')
        category_item = get_category_item_by_id(category_item_id)

        if category_item and session['user_id'] == category_item.created_by_id:
            return function(*args, **kwargs)
        else:
            flash('You are not authorized to access this resource')
            return redirect(url_for('showCategoryCatalog',
                            category_id=category_item.category_id))
    return wrapper

# decorators end

# login handlers start


@app.route('/login/')
def login():

    if 'user_id' in session:
        return redirect(url_for('showCatalog'))

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return render_template('login.html', STATE=state)

# used for google plus sign in


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('google_client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    google_client_id = json.loads(open('google_client_secrets.json', 'r')
                                  .read())['web']['client_id']
    if result['issued_to'] != google_client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = session.get('access_token')
    stored_gplus_id = session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    session['access_token'] = credentials.access_token
    session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    session['provider'] = 'google'
    session['username'] = data['name']
    session['picture'] = data['picture']
    session['email'] = data['email']
    session['logged_in'] = True

    user = get_user_by_email(session['email'])

    if not user:
        user = add_new_user(session)

    session['user_id'] = user.id

    output = ''
    output += '<h1>Welcome, '
    output += session['username']
    output += '!</h1>'
    output += '<img src="'
    output += session['picture']
    output += '"'
    flash("you are now logged in as %s" % session['username'])
    return output

# used for disconnecting from google plus


@app.route('/gdisconnect')
def gdisconnect():
    access_token = session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print session['username']
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# used to connect with fb login


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/v2.9/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    print url
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.9/me"
    # strip expire tag from access token
    data = json.loads(result)
    token = 'access_token=' + data['access_token']

    url = 'https://graph.facebook.com/v2.9/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    session['provider'] = 'facebook'
    session['username'] = data["name"]
    session['email'] = data["email"]
    session['facebook_id'] = data["id"]
    session['logged_in'] = True

    stored_token = token.split("=")[1]
    session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.9/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    session['picture'] = data["data"]["url"]

    # see if user exists
    user = get_user_by_email(session['email'])

    if not user:
        create_new_user(session['username'], session['email'],
                        session['picture'])
        user = get_user_by_email(session['email'])

    session['user_id'] = user.id

    output = ''
    output += '<h1>Welcome, '
    output += session['username']

    output += '!</h1>'
    output += '<img src="'
    output += session['picture']
    output += '"'

    flash("Now logged in as %s" % session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = session['facebook_id']
    # The access token must me included to successfully logout
    access_token = session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/logout')
def logout():
    if 'provider' in session:
        if session['provider'] == 'google':
            gdisconnect()
            del session['gplus_id']
            del session['access_token']
        if session['provider'] == 'facebook':
            fbdisconnect()
            del session['facebook_id']
            del session['access_token']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        del session['provider']
        del session['logged_in']
    return redirect(url_for('showCatalog'))

# login handlers end

# business logic handlers start


@app.route('/')
@app.route('/catalog/')
def showCatalog():

    categories = get_all_categories()
    items = get_latest_items()

    return render_template('catalog.html', categories=categories,
                           items=items, selected_category='Latest')


@app.route('/addcategory/', methods=['POST', 'GET'])
@user_logged_in
def addCategory():

    if request.method == 'POST':

        category_name = request.form["category_name"]
        category = add_category(category_name, session['user_id'])

        return redirect(url_for('showCategoryCatalog',
                        category_id=category.id))

    else:

        return render_template('add_category.html')


@app.route('/editcategory/<int:category_id>/', methods=['POST', 'GET'])
@user_logged_in
@can_edit_category
def editCategory(category_id):

    if request.method == 'POST':

        category_name = request.form["category_name"]
        category = edit_category(category_id, category_name)

        return redirect(url_for('showCategoryCatalog',
                        category_id=category.id))

    else:

        category = get_category_by_id(category_id)
        return render_template('edit_category.html', category=category)


@app.route('/deletecategory/<int:category_id>/', methods=['POST', 'GET'])
@user_logged_in
@can_edit_category
def deleteCategory(category_id):
    if request.method == 'POST':
        delete_category(category_id)
        return redirect(url_for('showCatalog'))
    else:
        category = get_category_by_id(category_id)
        return render_template('delete_category.html', category=category)


@app.route('/catalog/<int:category_id>')
def showCategoryCatalog(category_id):

    categories = get_all_categories()
    items = get_items_by_category(category_id)
    selected_category = get_category_by_id(category_id)

    return render_template('catalog.html', categories=categories, items=items,
                           selected_category=selected_category.name)


@app.route('/showitemdetail/<int:category_item_id>')
def showItemDetail(category_item_id):

    category_item = get_category_item_by_id(category_item_id)
    return render_template('item.html', category_item=category_item)


@app.route('/addcategoryitem/<selected_category>', methods=['POST', 'GET'])
@user_logged_in
def addCategoryItem(selected_category):

    if request.method == 'POST':

        item_name = request.form["item_name"]
        item_description = request.form["item_description"]
        category_id = request.form["category_id"]

        add_category_item(item_name, item_description,
                          category_id, session['user_id'])

        return redirect(url_for('showCategoryCatalog',
                        category_id=category_id))

    else:
        categories = get_all_categories()

        return render_template('add_category_item.html', categories=categories,
                               selected_category=selected_category)


@app.route('/editcategoryitem/<int:category_item_id>/',
           methods=['POST', 'GET'])
@user_logged_in
@can_edit_category_item
def editCategoryItem(category_item_id):

    if request.method == 'POST':

        item_name = request.form["item_name"]
        item_description = request.form["item_description"]
        category_id = request.form["category_id"]

        edit_category_item(category_item_id, item_name,
                           item_description, category_id)

        return redirect(url_for('showCategoryCatalog',
                        category_id=category_id))

    else:

        categories = get_all_categories()
        category_item = get_category_item_by_id(category_item_id)

        return render_template('edit_category_item.html',
                               categories=categories,
                               category_item=category_item)


@app.route('/deletecategoryitem/<int:category_item_id>/',
           methods=['POST', 'GET'])
@user_logged_in
@can_edit_category_item
def deleteCategoryItem(category_item_id):
    if request.method == 'POST':
        category_id = delete_category_item(category_item_id)
        return redirect(url_for('showCategoryCatalog',
                        category_id=category_id))
    else:
        category_item = get_category_item_by_id(category_item_id)
        return render_template('delete_category_item.html',
                               category_item=category_item)

# business logic handlers end

# json endpoints handlers start


@app.route('/categories/JSON')
def getCategoriesJSON():
    categories = get_all_categories()
    return jsonify(categories=[cat.serialize for cat in categories])


@app.route('/users/JSON')
def getUsersJSON():
    users = get_all_users()
    return jsonify(users=[user.serialize for user in users])


@app.route('/items/JSON')
def getItemsJSON():
    items = get_all_items()
    return jsonify(items=[item.serialize for item in items])


@app.route('/items/<int:category_id>/JSON')
def getCategoryItemsJSON(category_id):
    items = get_items_by_category(category_id)
    return jsonify(items=[item.serialize for item in items])


@app.route('/alldata/JSON')
def getAllDataJSON():

    categories = get_all_categories()
    category_data = []

    for cat in categories:

        data = cat.serialize

        items = get_items_by_category(cat.id)
        items_data = [item.serialize for item in items]
        data['items'] = items_data
        category_data.append(data)

    return jsonify(categories=category_data)

# json endpoints handlers end

if __name__ == '__main__':
    app.secret_key = "Item Catalog Super Secret Key"
    app.debug = True
    app.run(host="0.0.0.0", port=5000)
