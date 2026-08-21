import pandas as pd

from sklearn.model_selection import train_test_split

from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.naive_bayes import MultinomialNB

import joblib


# Load the dataset
data = pd.read_csv("dataset/malicious_phish.csv")

# Display the first 5 rows
print(data.head())

# Check dataset information
print(data.info())

# Check for missing values
print(data.isnull().sum())

# Input Feature (URL)
X = data["url"]

# Output Label (Website Type)
y = data["type"]

print(X.head())
print(y.head())

# Split dataset into Training and Testing

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("Training URLs :", len(X_train))
print("Testing URLs  :", len(X_test))

vectorizer = TfidfVectorizer()

# Convert training URLs into numerical features
X_train_vector = vectorizer.fit_transform(X_train)

# convert testing URLs into numerical features
X_test_vector = vectorizer.transform(X_test)

#save the vectorizer
joblib.dump(vectorizer, "vectorizer.pkl")

# Create Machine Learning Model
model = MultinomialNB()

# Train the model
model.fit(X_train_vector, y_train)

# Test the model
accuracy = model.score(X_test_vector, y_test)

print("Model Accuracy:", accuracy)

# Save the trained model
joblib.dump(model, "model.pkl")

print("Model saved successfully!")