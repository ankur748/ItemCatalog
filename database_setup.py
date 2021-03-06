from sqlalchemy import Column, ForeignKey, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

# This table will store all the users registered with the application


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    email = Column(String(200), unique=True, nullable=False)
    picture = Column(String(200))

    @property
    def serialize(self):

        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            "picture": self.picture
        }

# This table will store all the categories used in the application


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), unique=True, nullable=False)
    created_by_id = Column(Integer, ForeignKey('user.id'))
    created_by = relationship(User)

    @property
    def serialize(self):

        return {
            'id': self.id,
            'name': self.name,
            'created_by_id': self.created_by_id
        }

# This table will store items


class CategoryItem(Base):
    __tablename__ = "category_item"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(String(500), nullable=False)
    created_by_id = Column(Integer, ForeignKey('user.id'))
    created_by = relationship(User)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

    @property
    def serialize(self):

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category_id': self.category_id,
            'created_by_id': self.created_by_id
        }

engine = create_engine('sqlite:///ItemCatalog.db')
Base.metadata.create_all(engine)
