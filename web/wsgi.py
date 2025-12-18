"""WSGI entrypoint used by Gunicorn.

supervisord runs: `gunicorn -b 0.0.0.0:5000 wsgi:app`
"""

from app import app as app

# Common WSGI convention for other servers/tools.
application = app