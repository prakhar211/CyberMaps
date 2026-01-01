
import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    print("Error: GOOGLE_API_KEY not found in .env")
    exit(1)

genai.configure(api_key=api_key)

print(f"Checking access with key: {api_key[:10]}...")

try:
    print("\nListing available models:")
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f" - {m.name}")
    print("\nSuccess! Your API key works and can access the models above.")
except Exception as e:
    print(f"\nError listing models: {e}")
    print("\nTroubleshooting:")
    print("1. Ensure 'Google Generative AI API' is ENABLED in your Google Cloud Console.")
    print("2. Ensure the API key has no restrictions preventing access.")
