from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(10), nullable=False)   # 'url' or 'email'
    input_data = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(10), nullable=False)  # LOW / MEDIUM / HIGH
    reasons = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ScanResult {self.id} {self.scan_type} {self.risk_level}>'
