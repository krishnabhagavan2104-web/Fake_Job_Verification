from flask import Flask, render_template
from routes.scan_routes import scan_bp
from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(scan_bp, url_prefix="/api")

    @app.get("/")
    def home():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "service": "Fake Job Detector"
        }

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)