from flask import Flask, request, jsonify
from flask_cors import CORS
from detector import PhishingDetector
from email_detector import EmailDetector
from database import db, ScanResult
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# SQLite for simplicity (swap to MongoDB URI if needed)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

detector = PhishingDetector()
email_detector = EmailDetector()

with app.app_context():
    db.create_all()


@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    result = detector.analyze_url(url)

    # Save to DB
    scan = ScanResult(
        scan_type='url',
        input_data=url,
        risk_score=result['risk_score'],
        risk_level=result['risk_level'],
        reasons='; '.join(result['reasons']),
        timestamp=datetime.utcnow()
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify(result)


@app.route('/api/scan/email', methods=['POST'])
def scan_email():
    data = request.json
    email_content = data.get('email', '').strip()

    if not email_content:
        return jsonify({'error': 'Email content is required'}), 400

    result = email_detector.analyze_email(email_content)

    scan = ScanResult(
        scan_type='email',
        input_data=email_content[:500],
        risk_score=result['risk_score'],
        risk_level=result['risk_level'],
        reasons='; '.join(result['reasons']),
        timestamp=datetime.utcnow()
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify(result)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    total = ScanResult.query.count()
    phishing = ScanResult.query.filter_by(risk_level='HIGH').count()
    suspicious = ScanResult.query.filter_by(risk_level='MEDIUM').count()
    safe = ScanResult.query.filter_by(risk_level='LOW').count()
    url_scans = ScanResult.query.filter_by(scan_type='url').count()
    email_scans = ScanResult.query.filter_by(scan_type='email').count()

    # Recent scans
    recent = ScanResult.query.order_by(ScanResult.timestamp.desc()).limit(5).all()
    recent_list = [{
        'type': r.scan_type,
        'input': r.input_data[:60] + '...' if len(r.input_data) > 60 else r.input_data,
        'risk_level': r.risk_level,
        'risk_score': r.risk_score,
        'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M')
    } for r in recent]

    return jsonify({
        'total_scans': total,
        'phishing_detected': phishing,
        'suspicious': suspicious,
        'safe': safe,
        'url_scans': url_scans,
        'email_scans': email_scans,
        'recent_scans': recent_list
    })


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'PhishGuard API is running', 'version': '1.0.0'})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
