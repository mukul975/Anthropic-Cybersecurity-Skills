# API Reference: Detecting BEC with AI

## NLP Feature Extraction

| Feature | Description | BEC Signal |
|---------|-------------|------------|
| urgency_score | Ratio of urgency words to total | High = suspicious |
| pressure_score | Ratio of secrecy/pressure words | High = suspicious |
| financial_score | Ratio of financial terms | High = suspicious |
| authority_score | Ratio of executive title mentions | High = suspicious |
| caps_ratio | Uppercase character ratio | High = aggressive tone |
| unique_word_ratio | Vocabulary diversity metric | Low = template-like |

## scikit-learn Classification Pipeline

```python
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
    ("clf", RandomForestClassifier(n_estimators=100, random_state=42))
])
pipeline.fit(X_train, y_train)
predictions = pipeline.predict(X_test)
```

## Writing Style Analysis (Stylometry)

```python
# Sentence length distribution for author verification
import re, math
sentences = re.split(r'[.!?]+', text)
lengths = [len(s.split()) for s in sentences if s.strip()]
mean_len = sum(lengths) / len(lengths)
variance = sum((l - mean_len)**2 for l in lengths) / len(lengths)
std_dev = math.sqrt(variance)
```

## Microsoft Graph API - Suspicious Mail Rules

```http
GET https://graph.microsoft.com/v1.0/users/{id}/mailFolders/inbox/messageRules
Authorization: Bearer {token}

# Detect forwarding rules (T1114.003)
GET https://graph.microsoft.com/v1.0/users/{id}/mailFolders/inbox/messageRules?$filter=actions/forwardTo ne null
```

## Impersonation Signal Patterns

```python
# Mobile signature (creates urgency excuse)
r"sent from my (iphone|ipad|android|mobile)"
# Discourages verification
r"(please|kindly).*(do not|don't).*(reply|respond|call)"
# Unavailability excuse
r"(i am|i'm).*(in a meeting|traveling|on a flight)"
# Time pressure
r"(handle|process|complete).*(today|immediately|by end of day)"
```

## CLI Usage

```bash
python agent.py --file email_body.txt
python agent.py --file email_body.txt --baseline-file sender_style.json
```
