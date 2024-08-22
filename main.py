from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from catboost import CatBoostClassifier
import pandas as pd
import joblib
from URLFeatureExtraction import featureExtraction
import uvicorn
import mysql.connector
from mysql.connector import Error
from NewExtract import newExtraction

app = FastAPI()

def create_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',  # or your MySQL server host
            database='whitelist',
            user='root',
            password='skyline123'
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print("Error while connecting to MySQL", e)
        return None

def close_connection(connection):
    if connection.is_connected():
        connection.close()

# Load the CatBoost model
model_path = 'model.joblib'
model = joblib.load(model_path)

model1_path = 'modelPrunn.joblib'
model1 = joblib.load(model1_path)

# Serve static files (CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic model for input data
class URLData(BaseModel):
    url: str

@app.post("/check_whitelist")
async def check_whitelist(data: URLData):
    connection = create_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = connection.cursor()
        query = "SELECT * FROM table_whitelist WHERE url LIKE %s"
        cursor.execute(query, (data.url,))
        result = cursor.fetchone()
        if result:
            return {"url": data.url, "status": "whitelisted"}
        else:
            return {"url": data.url, "status": "not whitelisted"}
    except Error as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail="Database query failed")
    finally:
        close_connection(connection)

@app.post("/predict")
async def predict(data: URLData):
    try:
        print("Received URL:", data.url)
        features = featureExtraction(data.url)
        print("Extracted Features:", features)
        
        if len(features) != 16:
            raise ValueError("Extracted features length mismatch")
        
        feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                         'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                         'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards']
        
        features_df = pd.DataFrame([features], columns=feature_names)
        print("Features DataFrame:", features_df)
        
        # Check the length of both arrays
        print("Length of features array:", len(features))
        print("Length of DataFrame columns:", len(features_df.columns))
        
        # Make prediction
        prediction_proba = model.predict_proba(features_df)
        print("Prediction Probabilities:", prediction_proba)
        
        # Get the probability of the phishing class
        phishing_proba = prediction_proba[0][1]
        legitimate_proba = prediction_proba[0][0]
        
        # Translate prediction to label with confidence
        label = "phishing" if phishing_proba > 0.5 else "legitimate"
        confidence = max(phishing_proba, legitimate_proba) * 100
        
        return {
            "url": data.url,
            "prediction": label,
            "confidence": f"{confidence:.2f}%",
            "features": features,
            "features_df": features_df.to_dict(orient='records')
        }
    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predictNewModel")
async def predict(data: URLData):
    try:
        print("Received URL:", data.url)
        features = newExtraction(data.url)
        print("Extracted Features:", features)
        
        if len(features) != 9:
            raise ValueError("Extracted features length mismatch")
        
        feature_names = ['Have_At', 'URL_Length', 'URL_Depth', 
                         'TinyURL', 'Prefix/Suffix', 'Web_Traffic',
                         'Domain_Age', 'Domain_End', 'iFrame']
        
        features_df = pd.DataFrame([features], columns=feature_names)
        print("Features DataFrame:", features_df)
        
        # Check the length of both arrays
        print("Length of features array:", len(features))
        print("Length of DataFrame columns:", len(features_df.columns))
        
        # Make prediction
        prediction_proba = model1.predict_proba(features_df)
        print("Prediction Probabilities:", prediction_proba)
        
        # Get the probability of the phishing class
        phishing_proba = prediction_proba[0][1]
        legitimate_proba = prediction_proba[0][0]
        
        # Translate prediction to label with confidence
        label = "phishing" if phishing_proba > 0.5 else "legitimate"
        confidence = max(phishing_proba, legitimate_proba) * 100
        
        return {
            "url": data.url,
            "prediction": label,
            "confidence": f"{confidence:.2f}%",
            "features": features,
            "features_df": features_df.to_dict(orient='records')
        }
    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html") as f:
        return HTMLResponse(content=f.read(), status_code=200)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
