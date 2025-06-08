from flask import Flask
import logging
import threading
import queue
from .rules import load_rules

log_queue = queue.Queue()
lock = threading.Lock()

def create_app():
    app = Flask(__name__)
    load_rules(app)

    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.INFO)

    from .routes import setup_routes
    setup_routes(app)

    return app

