from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base,User,Category,CategoryItem

engine      = create_engine('sqlite:///ItemCatalog.db')
Base.metadata.bind=engine
DBSession   = sessionmaker(bind = engine)
session     = DBSession()

def get_all_categories():
    return session.query(Category).all()

def get_latest_items(pagesize = 10):
    return session.query(CategoryItem).order_by(CategoryItem.id.desc()).limit(pagesize)

def add_category(category_name, user_id = 1):
    category = Category(name = category_name, created_by_id = user_id)
    session.add(category)
    session.commit()

    return session.query(Category).filter_by(name = category_name).one()

def get_category_by_id(category_id):
    return session.query(Category).filter_by(id = category_id).one()

def edit_category(category_id, category_name):

    category        = get_category_by_id(category_id)
    category.name   = category_name

    session.add(category)
    session.commit()

    return category

def delete_category(category_id):

    category_items  = get_items_by_category(category_id)
    category        = get_category_by_id(category_id)

    for item in category_items:
        session.delete(category_items)

    session.delete(category)
    
    session.commit()

def get_items_by_category(category_id):
    return session.query(CategoryItem).filter_by(category_id = category_id).all()

def add_category_item(item_name, item_description, category_id, user_id = 1):
    category_item = CategoryItem(name = item_name, description = item_description, 
                                category_id = category_id, created_by_id = user_id)
    session.add(category_item)
    session.commit()

def get_category_item_by_id(category_item_id):
    return session.query(CategoryItem).filter_by(id = category_item_id).one()

def edit_category_item(category_item_id, item_name, item_description, category_id):

    category_item   = get_category_item_by_id(category_item_id)
    
    category_item.name          = item_name
    category_item.description   = item_description
    category_item.category_id   = category_id

    session.add(category_item)
    session.commit()

def delete_category_item(category_item_id):

    category_item       = get_category_item_by_id(category_item_id)

    session.delete(category_item)
    session.commit()

    return category_item.category_id