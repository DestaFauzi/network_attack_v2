from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/main/analyst', methods=['POST'])
def upload_pcap():
    if request.method == 'POST':
        pcap_file = request.files['pcapFile']
        pcap_file.save('uploads/' + pcap_file.filename)
        # Call the analyst.py script
        os.system('python analyst.py')
        return 'File uploaded and processed'
    else:
        return 'Method not allowed'

def get_data():
    # Placeholder for data retrieval logic
    data = {
        'timestamp': datetime.now().strftime('%d-%m-%Y %H:%M:%S'),
        'status': 'active'
    }
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
