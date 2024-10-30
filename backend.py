from flask import Flask, request, jsonify, render_template
import os
import tempfile
import nltk
nltk.download('punkt')
nltk.download('punkt_tab')
nltk.download('stopwords')
nltk.download('averaged_perceptron_tagger')

# Import or add your phishing detection functions here
from phishing_scan import scan_email_for_phishing

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan-email', methods=['POST'])                 
def scan_email():
    if 'emailFile' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['emailFile']

    # Save the uploaded file
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)
    
    # Run the phishing detection function on the file
    try:
        # Assuming scan_email_for_phishing returns a result message
        result = scan_email_for_phishing(file_path)
        message = f"Scan completed: {result}"
    except Exception as e:
        message = f"Error in scanning: {str(e)}"
    
    # Clean up the file after processing
    os.remove(file_path)
    return jsonify({"message": message})

if __name__ == '__main__':
    app.run(debug=True)
