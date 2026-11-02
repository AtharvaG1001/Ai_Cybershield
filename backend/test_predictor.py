import sys
sys.path.insert(0, '.')
from model_predictor import ModelPredictor
p = ModelPredictor()
urls = [
    'https://google.com',
    'https://www.southbankmosaics.com',
    'http://www.shprakserf.gq',
    'http://secure-paypal-login.xyz/verify',
]
for url in urls:
    r = p.predict(url)
    pred = r['prediction']
    ph = r['phishing_probability']
    le = r['legitimate_probability']
    print(url[:55], '->', pred, 'phish='+str(ph)+'%', 'legit='+str(le)+'%')
