# Slingshot-Elastic-Stack-
Used ELK Stack to trace the attacker’s activity: identified initial enumeration, detected exploitation of a vulnerable endpoint, followed privilege escalation, and tracked lateral movement across the system.



Slingway Inc., a leading toy company, has recently noticed suspicious activity on its e-commerce web server and potential modifications to its database. To investigate the suspicious activity, they've hired you as a SOC Analyst to look into the web server logs and uncover any instances of malicious activity.

To aid in your investigation, you've received an Elastic Stack instance containing logs from the suspected attack. Below, you'll find credentials to access the Kibana dashboard. Slingway's IT staff mentioned that the suspicious activity started on July 26, 2023.

By investigating and answering the questions below, we can create a timeline of events to lead the incident response activity. This will also allow us to present concise and confident findings that answer questions such as:

What vulnerabilities did the attacker exploit on the web server?
What user accounts were compromised?
What data was exfiltrated from the server?



### What was the attacker's IP?

 
# HTTP Request Log Details

This repository contains details of an HTTP request captured for reference and analysis.

## Request Information

- **HTTP Method:** GET  
- **URL:** /admin-login.php  
- **Response Status:** 200 OK  
- **IP Address:** 10.0.2.15  

## Description

The request was made to the `/admin-login.php` endpoint using the GET method. The server responded successfully with a status code `200`, indicating that the resource was found and returned correctly.

## Usage

This information can be used to verify server responses, debug requests, or track access to specific endpoints.

---

*Generated for tracking HTTP requests and responses.*

or u can use this <img width="1453" height="693" alt="image" src="https://github.com/user-attachments/assets/46c27ca4-ecb3-41ae-ba7c-990e0d0b3d57" />



### What was the first scanner that the attacker ran against the web server?


# Web Server Security Log Analysis

This repository contains an analysis of Apache web server logs collected from a suspicious IP address (10.0.2.15) probing the server. The purpose is to identify the type of scans or attacks performed and their sequence.

---

## Summary of Findings

- **First scanner detected:** Nmap  
  - Accessed path: `/.git/HEAD`  
  - HTTP response status: `404 Not Found`  
  - User-Agent: `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`  
  - Description: This is a typical initial reconnaissance scan where the attacker tries to discover hidden files or directories.

- **Second scanner detected:** Gobuster  
  - Accessed path: `/admin-login.php`  
  - HTTP response status: `401 Unauthorized`  
  - User-Agent: `Mozilla/5.0 (Gobuster)`  
  - Description: Gobuster is used to brute-force or discover hidden web directories or admin panels. The 401 status indicates the resource is protected and requires authentication.

---

## Logs and Fields Used

### Nmap Scan Example Log

```json
{
  "http.method": "GET",
  "http.url": "/.git/HEAD",
  "response.status": 404,
  "request.headers.User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
  "remote_address": "10.0.2.15"
}
```
<img width="905" height="804" alt="image" src="https://github.com/user-attachments/assets/7e433f93-cfa6-4b31-b572-2204c33d996d" />


### What was the User Agent of the directory enumeration tool that the attacker used on the web server?

# Directory Enumeration Tool User-Agent


## Answer
`Mozilla/5.0 (Gobuster)`

## Explanation
- The HTTP 401 Unauthorized responses were linked to directory enumeration attempts.
- The logs showed requests with the User-Agent: `Mozilla/5.0 (Gobuster)`.
- Gobuster is a common tool used for directory enumeration on web servers.

This confirms that the attacker used Gobuster as the directory enumeration tool.

### In total, how many requested resources on the web server did the attacker fail to find?


  
# Web Server Log Analysis — Detecting Failed Resource Requests (404)

This repository contains queries and analysis for identifying failed resource access attempts on a web server, specifically focusing on 404 Not Found HTTP responses from a specific IP address.

## Purpose

Use this analysis to detect when an attacker is scanning or probing for non-existent resources on your web server. Failed requests often indicate reconnaissance activity.

## KQL Query

```kql
transaction.remote_address: "10.0.2.15" AND http.method: (GET OR POST) AND response.status: 404
```

Query Explanation:
transaction.remote_address: "10.0.2.15"
Filters logs to include only requests from the attacker’s IP address.

http.method: (GET OR POST)
Includes both GET and POST HTTP request methods.

response.status: 404
Targets requests where the server responded with a 404 status code, indicating the resource was not found.
<img width="1084" height="503" alt="image" src="https://github.com/user-attachments/assets/3037bc22-226d-4c08-80e7-22e4c30c8780" />


### What is the flag under the interesting directory the attacker found?


# Web Server Attack Analysis

## Flag Discovery

During the analysis of the Apache logs, an interesting directory `/backups/` was discovered by the attacker using the directory enumeration tool **Gobuster**.

### Query Used:
Filtered logs for successful GET requests with the Gobuster User-Agent:

```kql
http.method: GET AND response.status: 200 AND request.headers.User-Agent: "Mozilla/5.0 (Gobuster)" AND http.url: "/backups/"
```
<img width="870" height="711" alt="image" src="https://github.com/user-attachments/assets/0bce27e5-886b-470a-bbf7-1f8e4acbc688" />



ANSWER a76637b62ea99acda12f5859313f539a

### What login page did the attacker discover using the directory enumeration tool?

## Discovered Login Page

Using directory enumeration with **Gobuster**, the attacker discovered a login page on the web server.

### KQL Query Used:
```kql
http.method: GET AND request.headers.User-Agent: "Mozilla/5.0 (Gobuster)" AND response.status: 401
```

<img width="1819" height="920" alt="image" src="https://github.com/user-attachments/assets/8e4caddb-4825-41b0-821a-3fb3df795ded" />

### What was the user agent of the brute-force tool that the attacker used on the admin panel?




## 🛡️ Brute-Force Attack Detection

### 🔍 What Was the User Agent of the Brute-Force Tool?

**Answer:**  
`hydra`

---

### 📄 How It Was Found

Using the Elastic Stack (ELK), the following KQL query was run in **Discover**:

```kql
http.method: GET AND http.url: "/admin-login.php" AND response.status: 200
This filtered all successful requests to the admin login page. Among the results, one request had the following User-Agent:

nginx
Copy
Edit
hydra
Hydra is a known brute-force tool, which strongly suggests that the attacker used it to automate login attempts on /admin-login.php.

```
### What username:password combination did the attacker use to gain access to the admin page?



## 🔐 Admin Login Credentials

- **Captured Authorization Header**:
Authorization: Basic YWRtaW46dGh4MTEzOA==

markdown
Copy
Edit

- **Decoded using Base64**:
admin:thx1138



- **Explanation**:
This header was found in the logs for a `GET /admin-login.php` request with a `200 OK` response, meaning the credentials were accepted. The base64 string in the `Authorization` field decodes to the valid `username:password` used by the attacker.

- **Final Answer**:
admin:thx1138

What flag was included in the file that the attacker uploaded from the admin directory?

## 🏴 Flag Found in the Admin Upload Directory

- **Context:**  
  The attacker successfully uploaded a PHP webshell to `/admin/upload.php?action=upload`. The POST request shows a multipart form-data upload of a file named `easy-simple-php-webshell.php`.

- **Flag Location:**  
  The uploaded webshell contains the flag inside its PHP code as a comment.

- **Flag:**  
THM{ecb012e53a58818cbd17a924769ec447}

csharp
Copy
Edit

- **How it was found:**  
The log entry for the POST request to `/admin/upload.php?action=upload` with `Authorization: Basic YWRtaW46dGh4MTEzOA==` includes the file content. Within the PHP code, the flag is commented out:

```php
// THM{ecb012e53a58818cbd17a924769ec447}
```


### What was the first command the attacker ran on the web shell?


<img width="1684" height="837" alt="image" src="https://github.com/user-attachments/assets/ab642a68-53d4-4061-a48c-d393b3d97e93" />


### Question:  
What file location on the web server did the attacker extract database credentials from using Local File Inclusion?

### Answer:  
The attacker extracted database credentials from the file located at:  
`/etc/phpmyadmin/config-db.php`

### Explanation:  
By filtering the logs for requests under `/admin/*`, we noticed several path traversal attempts in the `http.url` field. These requests repeatedly accessed the file `/etc/phpmyadmin/config-db.php`, which is known to contain database credentials. This confirms that the attacker exploited a Local File Inclusion vulnerability to extract the database credentials from this file.



### What directory did the attacker use to access the database manager?


<img width="430" height="403" alt="image" src="https://github.com/user-attachments/assets/5de727cc-b919-4c85-932e-3a8f5e32a0f4" />



### Answer:  
The attacker accessed the database manager through the directory:  
`/phpmyadmin`

### Explanation:  
By analyzing the Apache logs filtered under `/admin/*`, several requests were made to the `phpmyadmin` directory, which is a common web interface for managing MySQL databases. This confirms that the attacker used `/phpmyadmin` to access and manage the database.

### What was the name of the database that the attacker exported?



### Answer:  
The attacker exported the database named:  
`customer_credit_cards`

### Explanation:  
By analyzing the logs under the `/phpmyadmin/*` directory, several requests indicate access to the database structure and export operations. Specifically, requests to URLs such as `/phpmyadmin/db_structure.php` include parameters showing the database name `customer_credit_cards`, confirming it as the targeted and exported database.


<img width="1847" height="812" alt="image" src="https://github.com/user-attachments/assets/46fb3193-3664-49da-a1af-c62e31be69da" />


### What flag does the attacker insert into the database?






<img width="1828" height="708" alt="image" src="https://github.com/user-attachments/assets/50243ceb-802b-47a3-a9ee-5b7b3ee38810" />

decoded 

<img width="957" height="280" alt="image" src="https://github.com/user-attachments/assets/946ef8ad-08fd-41aa-ad0b-51ee3d295db3" />

## Answer

The attacker inserted the following flag into the database:

c6aa3215a7d519eeb40a660f3b76e64c


## Evidence

- The flag was inserted into the `credit_cards` table in the `customer_credit_cards` database.
- The insertion occurred via this SQL query found in the Apache logs:

```sql
INSERT INTO `credit_cards` (`card_number`, `cardholder_name`, `expiration_date`, `cvv`)
VALUES ('000', 'c6aa3215a7d519eeb40a660f3b76e64c', '000', '000');
```


