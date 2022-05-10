# webapp-flask-oauth2-cloudrun
This is an simple web app to demonstrate how to use OAuth 2.0 authorization to access user info. \
To mimic an on-prem web site leverage cloud identity/google identity to achieve the authentication purpose. \
This example can be run locally, or deployed to Google Cloud Run. 


# Create authorization credentials

Go GCP Console:
1. Go to the Credentials page
2. Create credentials > OAuth client ID.
3. Choose the Web application application type.
4. Fill in authorized redirect uri, then create. \
    For demo purpose, authorized redirect uri could be `http://localhost:8080` if you run the app locally. Or, it would be `https://<serviceName>-<projectHash>-<region>.run.app/oauth2callback` if you deploy it to cloud run 

After creating your credentials, download the client_secret.json file from the API Console. Securely store the file in a location that only your application can access (for demo purpose).\
[Official Google Document](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred)


# Deploy locally 
```sh
python3 main.py
```
Run the web app locally, then visit the page via http://localhost:8080


# Deploy to Cloud Run
```sh
gcloud run deploy <serviceName> --source .
```
Answer y to the question `Allow unauthenticated invocations` \
After deployment successfully, it will show the service url in the end of execution result. It looks like `https://<my-service-name>-<random-characters>.a.run.app`\
Go back to the GCP Credentials page, and add the authorized redirect uri based on the service url. \
The authorized redirect uri should be like `https://<my-service-name>-<random-characters>.a.run.app/oauth2callback`