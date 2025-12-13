from backend.markov import predictor

def test_prediction():
    print("Testing Markov Prediction...")
    next_steps = predictor.predict_next("Initial Access")
    print(f"Next after Initial Access: {next_steps}")
    assert len(next_steps) > 0
    assert next_steps[0][0] == "Execution"
    
    next_steps_lat = predictor.predict_next("Lateral Movement")
    print(f"Next after Lateral Movement: {next_steps_lat}")
    assert len(next_steps_lat) > 0
    print("Markov Test Passed!")

if __name__ == "__main__":
    test_prediction()
