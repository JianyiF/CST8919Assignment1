# Assignment 1: Securing and Monitoring an Authenticated Flask App


## Part 1: App Enhancements & Deployment
Use existing Autho integration from lab1, to enable azure service deployment, add URL to Auth0
```bash
http://localhost:3000/callback,
https://cst8919assignment1demo.azurewebsites.net/callback,
https://cst8919assignment1demo.azurewebsites.net/callback/,
http://cst8919assignment1demo.azurewebsites.net/callback,
http://cst8919assignment1demo.azurewebsites.net/callback/
```
for callback url
and
```bash
http://localhost:3000, https://cst8919assignment1demo.azurewebsites.net/,
https://cst8919assignment1demo.azurewebsites.net,
http://cst8919assignment1demo.azurewebsites.net,
http://cst8919assignment1demo.azurewebsites.net/
```
for logout url
Example logs from Auth0
![image](https://github.com/user-attachments/assets/38910211-6133-4e6c-a638-1c813cbbf498)

Run Docker image to build up the environment
```bash
sh exec.sh
```
Deploy the app using azure Web App
![image](https://github.com/user-attachments/assets/111cca6e-584a-49ef-9ba2-f97629a3fda6)



## Part 2: Monitoring & Detection
Create a Log Analytics Workspace
![image](https://github.com/user-attachments/assets/fe1581fc-1ecd-4e5f-97b9-74c35158e9f4)
Enable:AppServiceConsoleLogs, AppServiceHTTPLogs (optional), Send to the Log Analytics workspace.
![image](https://github.com/user-attachments/assets/31abb5df-9910-49d6-bf95-6a0cd7a91134)
Develop a http app using REST client to send request to Web App
```http
### Home Page (public)
GET https://cst8919assignment1demo.azurewebsites.net/
Accept: text/html


### Protected Route (Unauthenticated Access - Simulates Unauthorized)
GET https://cst8919assignment1demo.azurewebsites.net/protected
Accept: text/html


### Simulated Login Redirect (won't work fully in REST client)
GET https://cst8919assignment1demo.azurewebsites.net/login
Accept: text/html


### Callback URL Access (unauthorized without Auth0 context)
GET https://cst8919assignment1demo.azurewebsites.net/callback
Accept: text/html


### Logout (clears session)
GET https://cst8919assignment1demo.azurewebsites.net/logout
Accept: text/html
```
The log in request can be inspect in log stream
![image](https://github.com/user-attachments/assets/31d55772-27f1-4fd5-a4aa-425ca9afefc6)
Create a KQL query to find failed login attempts.
```query
AppServiceConsoleLogs
| where TimeGenerated > ago(15m)
| where ResultDescription contains "unauthorized_access"
| extend json = trim_start("WARNING:app:", ResultDescription)
| extend data = parse_json(json)
| project TimeGenerated, IP = tostring(data.ip), UserId = tostring(data.user_id), Email = tostring(data.email), Path = tostring(data.path), Timestamp = tostring(data.timestamp)

```
![image](https://github.com/user-attachments/assets/2fc14712-6bbe-4795-a7f9-fbc8b1502de1)
Create an Alert rule using the KQL query created, and setup email notification if failed more than 5 attempts.
![image](https://github.com/user-attachments/assets/29755314-1a89-4725-9780-cdd72857d650)
![image](https://github.com/user-attachments/assets/40ce4adc-a3e8-43a3-b704-2f471cf564cc)

## YouTube Link
https://youtu.be/wHeKWvpUrF0


