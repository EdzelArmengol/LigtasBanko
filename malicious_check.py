import pandas as pd
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn import metrics
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import xgboost as xgb
from lightgbm import LGBMClassifier
import os
import seaborn as sns
from wordcloud import WordCloud

df=pd.read_csv('Armengol-Fadrigalan-Marasigan-BCS34.csv')

df.type.value_counts()

import re
#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))

"""## 3.1.2 "@" Symbol in URL

Checks for the presence of '@' symbol in the URL. Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.
"""

def count_atrate(url):

    return url.count('@')

df['count@'] = df['url'].apply(lambda i: count_atrate(i))

"""## 3.1.3 Length of URL

Computes the length of the URL. Phishers can use long URL to hide the doubtful part in the address bar.
"""

def url_length(url):
    return len(str(url))


#Length of URL
df['url_length'] = df['url'].apply(lambda i: url_length(i))

"""## 3.1.4 Redirection "//" in URL

The number of the embedded domains can be helpful in detecting malicious URLs. It can be done by checking the occurrence of “//” in the URL.
"""

from urllib.parse import urlparse

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

df['count_embed_domain'] = df['url'].apply(lambda i: no_of_embed(i))

"""## 3.1.5 HTTP/HTTPS in URLs

Generally malicious URLs do not use HTTPS protocols as it generally requires user credentials and ensures that the website is safe for transactions. So, the presence or absence of HTTPS protocol in the URL is an important feature.

Most of the time, phishing or malicious websites have more than one HTTP in their URL whereas safe sites have only one HTTP.
"""

def count_https(url):
    return url.count('https')

df['count-https'] = df['url'].apply(lambda i : count_https(i))

def count_http(url):
    return url.count('http')

df['count-http'] = df['url'].apply(lambda i : count_http(i))

"""## 3.1.6 Using URL Shortening Services “TinyURL”

This feature is created to identify whether the URL uses URL shortening services like bit. \ly, goo.gl, go2l.ink, etc
"""

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0


df['short_url'] = df['url'].apply(lambda i: shortening_service(i))

def count_dot(url):
    count_dot = url.count('.')
    return count_dot

df['count.'] = df['url'].apply(lambda i: count_dot(i))

def count_www(url):
    url.count('www')
    return url.count('www')

df['count-www'] = df['url'].apply(lambda i: count_www(i))

def count_per(url):
    return url.count('%')

df['count%'] = df['url'].apply(lambda i : count_per(i))

def count_ques(url):
    return url.count('?')

df['count?'] = df['url'].apply(lambda i: count_ques(i))

def count_hyphen(url):
    return url.count('-')

df['count-'] = df['url'].apply(lambda i: count_hyphen(i))

def count_equal(url):
    return url.count('=')

df['count='] = df['url'].apply(lambda i: count_equal(i))

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

df['count-digits']= df['url'].apply(lambda i: digit_count(i))

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


df['count-letters']= df['url'].apply(lambda i: letter_count(i))

from urllib.parse import urlparse

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))

from googlesearch import search

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0
df['google_index'] = df['url'].apply(lambda i: google_index(i))

#Hostname Length
def hostname_length(url):
    return len(urlparse(url).netloc)

df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))

import nltk
from nltk.tokenize import RegexpTokenizer

#Importing dependencies
from urllib.parse import urlparse
from tld import get_tld
import os.path

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

df['fd_length'] = df['url'].apply(lambda i: fd_length(i))

#Length of Top Level Domain
df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))


def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))

"""## 3.5 TF-IDF"""

from sklearn.feature_extraction.text import TfidfVectorizer

# Function to create a TF-IDF model
def create_tfidf_model(data):
    tfidf_model = TfidfVectorizer(max_features=500)
    X_tfidf = tfidf_model.fit_transform(data).toarray()
    return X_tfidf, tfidf_model

df.head()

df = df.drop("tld", axis=1)

df.columns

df['type'].value_counts()

"""## Target Encoding"""

from sklearn.preprocessing import LabelEncoder

lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])
df["type_code"].value_counts()

tfidf_models = {}
important_columns_dict = {}

"""## Creation of Feature & Target"""

#Predictor Variables
# filtering out google_index as it has only 1 value
X = df[['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@', 'count_embed_domain', 'short_url', 'count-https',
       'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
       'hostname_length', 'fd_length', 'tld_length', 'count-digits',
       'count-letters']]

#Target Variable
y = df['type_code']

X_tfidf, tfidf_model = create_tfidf_model(df['url'])
X_combined = np.concatenate((X, X_tfidf), axis=1)

columns = list(X.columns) + [f"tfidf_{i}" for i in range(X_tfidf.shape[1])]
X = pd.DataFrame(X_combined, columns=columns)

X.head()

X.columns

"""## Train Test Split

"""

from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True, random_state=5)

import warnings

# Filter out specific UserWarnings
warnings.filterwarnings("ignore", category=UserWarning, message=".*feature_fraction.*")
warnings.filterwarnings("ignore", category=UserWarning, message=".*colsample_bytree.*")

# Create a pipeline with SMOTE and the RandomForestClassifier
model = LGBMClassifier(n_estimators=100, num_leaves=31, max_depth=-1, feature_fraction=0.8, colsample_bytree=0.8)
pipeline = Pipeline(steps=[('smote', SMOTE(sampling_strategy='auto')), ('model', model)])

warnings.resetwarnings()

# Fit the pipeline on the training data
pipeline.fit(X_train, y_train)

# Set feature names after fitting
pipeline.named_steps['model'].feature_names = list(X_train.columns)

# Make predictions on the test set
y_pred = pipeline.predict(X_test)

"""## Model Building"""

"""## 2. Light GBM Classifier"""

LGB_C = LGBMClassifier(objective='binary', boosting_type='gbdt', n_jobs=5, verbosity=-1, random_state=5, max_features='sqrt')
LGB_C.fit(X_train, y_train)
y_pred_lgb = LGB_C.predict(X_test)


def main(url, tfidf_model):
    status = []

    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_embed(url))
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    status.append(tld_length(tld))

    # Assuming tfidf_model is a pre-fit TF-IDF model
    tfidf_features = tfidf_model.transform([url]).toarray()
    status += tfidf_features.tolist()[0]

    return status

import time

def get_prediction_from_url_timed(test_url):
    start_time = time.time()

    features_test = main(test_url, tfidf_model)
    features_test = np.array(features_test).reshape((1, -1))

    pred = LGB_C.predict(features_test)

    end_time = time.time()
    elapsed_time = end_time - start_time

    # Get feature importances from Light GBM
    feat_importances = pd.Series(LGB_C.feature_importances_, index=columns)
    top_features = feat_importances.sort_values(ascending=False).head(3)

    if int(pred[0]) == 0:
        res = "SAFE"
    elif int(pred[0]) == 1.0:
        res = "PHISHING"

    print(f"Prediction for {test_url}: {res}")
    print(f"Top 3 Features:")
    for feature, importance in top_features.items():
        print(f"{feature}: {importance}")

    print(f"Time taken: {elapsed_time:.4f} seconds\n")

    return res, dict(top_features)