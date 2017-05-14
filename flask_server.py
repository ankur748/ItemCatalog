from flask import Flask, render_template, flash, redirect, request, url_for
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

app         = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Application Catalog"

#decorators start
def user_logged_in(function):
    @wraps(function)
    def wrapper (*args, **kwargs):
        if 'user_id' in session:
            return function(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrapper

def can_edit_category(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if 'user_id' not in session:
            return redirect(url_for('login'))

        category_id = kwargs.get('category_id')
        category    = get_category_by_id(category_id)

        if category and session['user_id'] == category.created_by_id:
            return function(*args, **kwargs)
        else:
            return redirect(url_for('showCatalog'))
    return wrapper

def can_edit_category_item(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if 'user_id' not in session:
            return redirect(url_for('login'))

        category_item_id    = kwargs.get('category_item_id')
        category_item       = get_category_item_by_id(category_item_id)

        if category_item and session['user_id'] == category_item.created_by_id:
            return function(*args, **kwargs)
        else:
            return redirect(url_for('showCategoryCatalog', category_id = category_item.category_id))
    return wrapper

#decorators end

#handlers start
@app.route('/login/')
def login():

    if 'user_id' in session:
        return redirect(url_for('showCatalog'))

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    
    return render_template('login.html', STATE = state)

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
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = session.get('access_token')
    stored_gplus_id = session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % session['username'])
    return output

@app.route('/gdisconnect')
def gdisconnect():
    access_token = session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print session['username']
    if access_token is None:
 	print 'Access Token is None'
    	response = make_response(json.dumps('Current user not connected.'), 401)
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

    # The token must be stored in the session in order to properly logout, let's strip out the information before the equals sign in our token
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
        create_new_user(session['username'], session['email'], session['picture'])
        user = get_user_by_email(session['email'])
    
    session['user_id'] = user.id

    output = ''
    output += '<h1>Welcome, '
    output += session['username']

    output += '!</h1>'
    output += '<img src="'
    output += session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % session['username'])
    return output

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = session['facebook_id']
    # The access token must me included to successfully logout
    access_token = session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# Disconnect based on provider
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

@app.route('/')
@app.route('/catalog/')
def showCatalog():

    categories  = get_all_categories()
    items       = get_latest_items()

    return render_template('catalog.html', categories = categories, items = items, selected_category = 'Latest')

@app.route('/addcategory/', methods=['POST', 'GET'])
@user_logged_in
def addCategory():

    if request.method == 'POST':

        category_name   = request.form["category_name"]
        category        = add_category(category_name, session['user_id'])

        return redirect(url_for('showCategoryCatalog', category_id = category.id))

    else:

        return render_template('add_category.html')

@app.route('/editcategory/<int:category_id>/', methods=['POST', 'GET'])
@can_edit_category
def editCategory(category_id):
    
    if request.method == 'POST':

        category_name   = request.form["category_name"]
        category        = edit_category(category_id, category_name)

        return redirect(url_for('showCategoryCatalog', category_id = category.id))

    else:

        category = get_category_by_id(category_id)
        return render_template('edit_category.html', category = category)

@app.route('/deletecategory/<int:category_id>/', methods=['POST', 'GET'])
@can_edit_category
def deleteCategory(category_id):
    
    if request.method == 'POST':

        delete_category(category_id)
        return redirect(url_for('showCatalog'))

    else:
        
        category = get_category_by_id(category_id)
        return render_template('delete_category.html', category = category)

@app.route('/catalog/<int:category_id>')
def showCategoryCatalog(category_id):

    categories          = get_all_categories()
    items               = get_items_by_category(category_id)
    selected_category   = get_category_by_id(category_id)

    return render_template('catalog.html', categories = categories, items = items
                                        , selected_category = selected_category.name)

@app.route('/showitemdetail/<int:category_item_id>')
def showItemDetail(category_item_id):

    category_item = get_category_item_by_id(category_item_id)
    return render_template('item.html', category_item = category_item)

@app.route('/addcategoryitem/<selected_category>', methods=['POST', 'GET'])
@user_logged_in
def addCategoryItem(selected_category):

    if request.method == 'POST':

        item_name           = request.form["item_name"]
        item_description    = request.form["item_description"]
        category_id         = request.form["category_id"]

        add_category_item(item_name, item_description, category_id, session['user_id'])

        return redirect(url_for('showCategoryCatalog', category_id = category_id))

    else:
        categories          = get_all_categories()

        return render_template('add_category_item.html', categories = categories
                                    , selected_category = selected_category)

@app.route('/editcategoryitem/<int:category_item_id>/', methods=['POST', 'GET'])
@can_edit_category_item
def editCategoryItem(category_item_id):
    
    if request.method == 'POST':

        item_name           = request.form["item_name"]
        item_description    = request.form["item_description"]
        category_id         = request.form["category_id"]

        edit_category_item(category_item_id, item_name, item_description, category_id)

        return redirect(url_for('showCategoryCatalog', category_id = category_id))

    else:

        categories          = get_all_categories()
        category_item       = get_category_item_by_id(category_item_id)

        return render_template('edit_category_item.html', categories = categories, 
                                    category_item = category_item)

@app.route('/deletecategoryitem/<int:category_item_id>/', methods=['POST', 'GET'])
@can_edit_category_item
def deleteCategoryItem(category_item_id):
    
    if request.method == 'POST':

        category_id = delete_category_item(category_item_id)
        return redirect(url_for('showCategoryCatalog', category_id = category_id))

    else:
        
        category_item = get_category_item_by_id(category_item_id)
        return render_template('delete_category_item.html', category_item = category_item)

#handlers end

if __name__ == '__main__':
    app.secret_key = "Item Catalog Super Secret Key"
    app.debug = True
    app.run(host="0.0.0.0", port=5000)