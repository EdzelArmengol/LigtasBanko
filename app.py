from flask import Flask, render_template, request
from malicious_check import get_prediction_from_url_timed

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html', prediction=None, top_features=None)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    prediction, top_features = get_prediction_from_url_timed(url)

    return render_template('index.html', prediction=prediction, top_features=top_features)

if __name__ == '__main__':
    app.run(debug=True)
