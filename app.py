from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime
import os
import sys

# Add main directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'main'))

# Import analyst functions
from main.analyst import analyze_pcap, generate_report

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/main/analyst', methods=['GET', 'POST'])
def upload_pcap():
    if request.method == 'GET':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'pcapFile' not in request.files:
                return jsonify({'error': 'No file uploaded', 'status': 'failed'}), 400
            
            pcap_file = request.files['pcapFile']
            
            # Check if file is selected
            if pcap_file.filename == '':
                return jsonify({'error': 'No file selected', 'status': 'failed'}), 400
            
            # Validate file extension
            allowed_extensions = {'.pcap', '.pcapng'}
            file_ext = os.path.splitext(pcap_file.filename)[1].lower()
            if file_ext not in allowed_extensions:
                return jsonify({'error': 'Invalid file format. Only .pcap and .pcapng files are allowed', 'status': 'failed'}), 400
            
            # Create uploads directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            # Save uploaded file with timestamp to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{pcap_file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            pcap_file.save(file_path)
            
            # Analyze PCAP file
            print(f"Analyzing file: {file_path}")
            results = analyze_pcap(file_path)
            
            # Check if analysis was successful
            if 'error' in results:
                return jsonify(results), 500
            
            # Generate report
            report = generate_report(results)
            
            # Always return JSON for consistency
            return jsonify({
                'status': 'success',
                'results': results,
                'report': report,
                'filename': filename
            })
            
            # Check if request is AJAX (from fetch API)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
                return jsonify({
                    'status': 'success',
                    'results': results,
                    'report': report,
                    'filename': filename
                })
            else:
                # For direct form submission, redirect to dashboard
                return render_template('dashboard.html', 
                                     analysis_results=results, 
                                     filename=filename,
                                     report=report)
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            return jsonify({'error': f'Analysis failed: {str(e)}', 'status': 'failed'}), 500
    
    return jsonify({'error': 'Method not allowed', 'status': 'failed'}), 405

@app.route('/api/data')
def get_data():
    # API endpoint for getting analysis data
    data = {
        'timestamp': datetime.now().strftime('%d-%m-%Y %H:%M:%S'),
        'status': 'active'
    }
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
