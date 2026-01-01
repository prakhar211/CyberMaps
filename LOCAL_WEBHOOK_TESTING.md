
# Local Webhook Testing with Ngrok

To test Coralogix webhooks with your local development server, you must expose your local port 8000 to the internet.

1. **Install Ngrok** (if not already installed)
   ```bash
   brew install ngrok/ngrok/ngrok
   ```

2. **Authenticate Ngrok**
   Ngrok now requires a free account. 
   1. Sign up at [dashboard.ngrok.com](https://dashboard.ngrok.com/signup).
   2. Get your authtoken from [dashboard.ngrok.com/get-started/your-authtoken](https://dashboard.ngrok.com/get-started/your-authtoken).
   3. Run the following command:
      ```bash
      ngrok config add-authtoken <YOUR_TOKEN>
      ```

3. **Start the Tunnel**
   Run this in a new terminal tab:
   ```bash
   ngrok http 8000
   ```

3. **Get your Public URL**
   Copy the URL that looks like `https://xxxx-xxxx.ngrok-free.app`.

4. **Update Coralogix**
   
   **A. URL**: 
   Enter the base URL *without* the API key:
   `https://xxxx-xxxx.ngrok-free.app/api/webhooks/coralogix`

   **B. Headers**:
   In the **Editing message** > **Headers** section, add your API key:
   ```json
   "Content-Type": "application/json",
   "X-CyberMaps-API-Key": "YOUR_API_KEY"
   ```
   *(Replace `YOUR_API_KEY` with your actual secret)*

> **Note**: If you restart ngrok, the URL will change. You must update Coralogix each time.
