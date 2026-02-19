import functools

from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.query import Query
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import MetaData
from sqlalchemy.orm import object_session
from sqlalchemy.pool import NullPool
from sqlalchemy_searchable import SearchQueryMixin, make_searchable, vectorizer

from redash import settings
from redash.stacklet.auth import get_env_db
from redash.utils import json_dumps, json_loads, get_schema


class RedashSQLAlchemy(SQLAlchemy):
    def _make_engine(self, bind_key, options, app):
        # Stacklet customization: Override engine creation to use custom connection logic
        # See redash.stacklet.auth.get_env_db() for implementation details
        engine = get_env_db()
        if engine is not None:
            return engine
        if settings.SQLALCHEMY_DISABLE_POOL:
            # NullPool does not support these options; remove any Flask-SQLAlchemy defaults
            for key in ("pool_size", "max_overflow", "pool_timeout", "pool_recycle"):
                options.pop(key, None)
        return super(RedashSQLAlchemy, self)._make_engine(bind_key, options, app)


md = None
if settings.SQLALCHEMY_DATABASE_SCHEMA:
    md = MetaData(schema=settings.SQLALCHEMY_DATABASE_SCHEMA)


class SearchBaseQuery(Query, SearchQueryMixin):
    """
    The SQA query class to use when full text search is wanted.
    """


_engine_options = {
    "execution_options": {"schema_translate_map": {None: get_schema()}},
    "json_serializer": json_dumps,
}
if settings.SQLALCHEMY_ENABLE_POOL_PRE_PING:
    _engine_options["pool_pre_ping"] = True
if settings.SQLALCHEMY_DISABLE_POOL:
    _engine_options["poolclass"] = NullPool

db = RedashSQLAlchemy(
    session_options={"expire_on_commit": False},
    engine_options=_engine_options,
    metadata=md,
    query_class=SearchBaseQuery,
)

# Make sure the SQLAlchemy mappers are all properly configured first.
# This is required by SQLAlchemy-Searchable as it adds DDL listeners
# on the configuration phase of models.
db.configure_mappers()

# listen to a few database events to set up functions, trigger updates
# and indexes for the full text search
make_searchable(db.metadata, options={"regconfig": "pg_catalog.simple"})


@vectorizer(db.Integer)
def integer_vectorizer(column):
    return db.func.cast(column, db.Text)


@vectorizer(UUID)
def uuid_vectorizer(column):
    return db.func.cast(column, db.Text)


Column = functools.partial(db.Column, nullable=False)

# AccessPermission and Change use a 'generic foreign key' approach to refer to
# either queries or dashboards.
# TODO replace this with association tables.
_gfk_types = {}


def gfk_type(cls):
    _gfk_types[cls.__tablename__] = cls
    return cls


class GFKBase:
    """
    Compatibility with 'generic foreign key' approach Peewee used.
    """

    object_type = Column(db.String(255))
    object_id = Column(db.Integer)

    _object = None

    @property
    def object(self):
        session = object_session(self)
        if self._object or not session:
            return self._object
        else:
            object_class = _gfk_types[self.object_type]
            self._object = session.query(object_class).filter(object_class.id == self.object_id).first()
            return self._object

    @object.setter
    def object(self, value):
        self._object = value
        self.object_type = value.__class__.__tablename__
        self.object_id = value.id


key_definitions = settings.dynamic_settings.database_key_definitions((db.Integer, {}))


def key_type(name):
    return key_definitions[name][0]


def primary_key(name):
    key_type, kwargs = key_definitions[name]
    return Column(key_type, primary_key=True, **kwargs)
