"""
Route Blueprints Registration
"""
from backend.routes.events import events_bp
from backend.routes.stats import stats_bp
from backend.routes.risk import risk_bp
from backend.routes.journey import journey_bp
from backend.routes.analysis import analysis_bp
from backend.routes.prediction import prediction_bp
from backend.routes.geo import geo_bp
from backend.routes.reset import reset_bp

def register_routes(app):
    """Register all API route blueprints to the Flask application."""
    app.register_blueprint(events_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(journey_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(prediction_bp)
    app.register_blueprint(geo_bp)
    app.register_blueprint(reset_bp)
