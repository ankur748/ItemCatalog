from sqlalchemy import Column, ForeignKey, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

#This table will store all the users registered with the application
class User(Base):
    __tablename__   = "user"

    id              = Column(Integer, primary_key = True)
    name            = Column(String(200), nullable = False)
    email           = Column(String(200), unique = True, nullable = False)
    picture         = Column(String(200))

#This table will store all the categories used in the application
class Category(Base):
    __tablename__   = "category"

    id              = Column(Integer, primary_key = True)
    name            = Column(String(200), unique = True, nullable = False)
    created_by_id   = Column(Integer, ForeignKey('user.id'))
    created_by      = relationship(User)

#This table will store items respective to a particular category stored in application
class CategoryItem(Base):
    __tablename__   = "category_item"

    id              = Column(Integer, primary_key = True)
    name            = Column(String(200), nullable = False)
    description     = Column(String(500), nullable = False)
    created_by_id   = Column(Integer, ForeignKey('user.id'))
    created_by      = relationship(User)
    category_id     = Column(Integer, ForeignKey('category.id'))
    category        = relationship(Category)

engine = create_engine('sqlite:///ItemCatalog.db')
Base.metadata.create_all(engine)