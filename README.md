Proposing a robust strategy, the study utilizes Term Frequency-Inverse Document Frequencies (TF-IDF) and machine learning for URL phishing detection. With a dataset comprising benign URLs from the top 52 Philippine banks and phishing URLs from PhishTank, the research showcases the efficacy of TF-IDF, especially with the Light GBM algorithm, which consistently outperforms others. This results in a notable accuracy surge from 99.71% to 99.86% and an enhanced F1 score from 99.84% to 99.92% with TF-IDF. The proposed ML and NLP model contribute to user awareness, aiming to protect Philippine bank customers from potential financial fraud by identifying patterns indicative of phishing attempts. The study underscores the urgency of addressing this issue in the Philippines, offering insights into the features of phishing URLs and proposing a reliable model with implications for user trust, online banking security, and broader cybersecurity measures.

Download all libraries in requirement.txt
Run "python app.py" to run the application in flask
Insert Philippine URL bank links to identify if the link is phishing or not.

Gaps:

  The Phishing detector model as of now only differentiates the characteristics of both phishing and safe Philippine URL bank links.
  
  Feature Engineering for:
  
    1. Address Bar Based Features
    2. Domain Based Features
    3. HTML & Javascript Based Features
  Are what the model learns from. However, it lacks the capabilities to delve deeper into the specific activities of websites or discern other characteristics that could enhance prediction accuracy and offer more insightful information for users.

  The dataset is also composed of 49,107 URLS and 4,994 safe URLS which poses a high imbalanced dataset.

  
