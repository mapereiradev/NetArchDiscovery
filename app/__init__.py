from flask import Flask
from .job_manager import JobManager

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me"
    # instancia global
    app.jobmanager = JobManager(report_dir="reports/output")
    # registra tu blueprint actual (ya lo tienes)
    from .routes.routes import main
    app.register_blueprint(main)
    return app
