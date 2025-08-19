from flask import Flask
from .job_manager import JobManager
from .routes.routes import main
from pathlib import Path

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me"
    base_dir = Path(__file__).resolve().parent
    report_dir = (base_dir / ".." / "reports" / "output").resolve()
    app.jobmanager = JobManager(report_dir=str(report_dir))

    app.register_blueprint(main)
    return app
