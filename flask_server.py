from flask import Flask, render_template, flash, redirect, request, url_for
from database_setup import *
from database_helper import *

app         = Flask(__name__)

@app.route('/')
@app.route('/catalog/')
def showCatalog():

    categories  = get_all_categories()
    items       = get_latest_items()

    return render_template('catalog.html', categories = categories, items = items, selected_category = None)

@app.route('/addcategory/', methods=['POST', 'GET'])
def addCategory():

    if request.method == 'POST':

        category_name   = request.form["category_name"]
        category        = add_category(category_name)

        return render_template('catalog.html', categories = categories, items = items, 
                                    selected_category = category)

    else:

        return render_template('add_category.html')

@app.route('/editcategory/<int:category_id>/', methods=['POST', 'GET'])
def editCategory(category_id):
    
    if request.method == 'POST':

        category_name   = request.form["category_name"]
        category        = edit_category(category_id, category_name)

        return render_template('catalog.html', categories = categories, items = items, 
                                    selected_category = category)

    else:

        category = get_category_by_id(category_id)
        return render_template('edit_category.html', category = category)

@app.route('/deletecategory/<int:category_id>/', methods=['POST', 'GET'])
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
                                        , selected_category = selected_category)

@app.route('/addcategoryitem/', methods=['POST', 'GET'])
def addCategoryItem():

    if request.method == 'POST':

        item_name           = request.form["item_name"]
        item_description    = request.form["item_description"]
        category_id         = request.form["category_id"]

        add_category_item(item_name, item_description, category_id)

        return redirect(url_for('showCategoryCatalog', category_id = category_id))

    else:

        return render_template('add_category_item.html')

@app.route('/editcategory/<int:category_item_id>/', methods=['POST', 'GET'])
def editCategoryItem(category_item_id):
    
    if request.method == 'POST':

        item_name           = request.form["item_name"]
        item_description    = request.form["item_description"]
        category_id         = request.form["category_id"]

        edit_category_item(category_item_id, item_name, item_description, category_id)

        return redirect(url_for('showCategoryCatalog', category_id = category_id))

    else:

        category_item = get_category_item_by_id(category_item_id)
        return render_template('edit_category_item.html', category_item = category_item)

@app.route('/deletecategory/<int:category_item_id>/', methods=['POST', 'GET'])
def deleteCategoryItem(category_item_id):
    
    if request.method == 'POST':

        category_id = delete_category_item(category_item_id)
        return redirect(url_for('showCategoryCatalog', category_id = category_id))

    else:
        
        category_item = get_category_item_by_id(category_item_id)
        return render_template('delete_category_item.html', category_item = category_item)

if __name__ == '__main__':
    app.secret_key = "Item Catalog Super Secret Key"
    app.debug = True
    app.run(host="0.0.0.0", port=5000)