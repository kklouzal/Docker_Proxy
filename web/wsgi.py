"""WSGI entrypoint used by Gunicorn.

supervisord runs: `python3 -m gunicorn -b 0.0.0.0:5000 wsgi:app`
"""

from app import app, install_admin_default_proxy_resolver

# Only the Admin UI process resolves the implicit proxy from the stored
# default selection; background services start on the first request, after
# this runs.
install_admin_default_proxy_resolver()

# Common WSGI convention for other servers/tools.
application = app
