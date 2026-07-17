# FRAUDETECTIVE - Fintech SOC Simulator

#### Video Demo: https://www.youtube.com/watch?v=ay6bLBLlhBU

#### Description

Hi, my name is Angel Alfonso Rodriguez Bolivar and this is my final project for CS50, the best course I have ever taken.

Fraud Detective is a SOC simulator I built because I worked for 2.5 years at Sutherland for Remitly on the Customer Protection team. Every day I was handling with fraud alerts, doing KYC checks, looking for money mules, account takeovers, gender mismatch red flags, and deciding whether to suspend accounts or let the money go through to the recipients.

I wanted to see if I can take my real experience and turn it into actual code. So I created a dashboard where you can generate realistic fraud alerts, see live charts, triage them with Suspend / Approve / Escalate buttons, and export everything to CSV file — just like I did in my job.

### What the project does
- Fraudetective generates fraud alerts using the same kind of rules I used every day at Remitly (high-risk corridors, gender mismatch, velocity, money mules, PEP/OFAC, brute-force, etc.)
- Fraudetective has a clean dashboard with two live charts (severity pie and alerts by rule type)
- Fraudetective lets you click Suspend, Approve or Escalate on any alert and the status changes + row color changes
- Fraudetective saves everything in SQLite so the alerts stay even if you refresh the page
- Fraudetective has an Export to CSV button so you can download the data
- Fraudetective looks and feels like a real SOC tool

### Technologies I used
- Flask (Python) for the backend
- SQLite for the database
- Jinja2 for the templates
- Bootstrap for the design
- Chart.js for the graphs
- JavaScript for the interactive parts and CSV export

### How this connects to my life
I spent 2.5 years doing exactly this kind of work at Remitly 48 hours a week. RemitGuard is me taking that experience and putting it into code. It also shows that I’m serious about moving into cybersecurity (SOC → Pentesting / Cloud Security).

### AI Assistance Disclosure
I used Grok (from xAI) to help me with code structure, fixing bugs, writing comments, and implementing the CSV export. But the main idea, the fraud rules, the triage logic, and all the important decisions were made by me based on my real job experience and knowledge. I reviewed and changed everything myself.

### Files
- layout.html → base template with navbar, footer and styles
- index.html → simple home page
- dashboard.html → the main SOC dashboard with charts and table
- app.py → all the backend logic, routes, database and rule engine

### How to run it
1. Clone the repo
2. pip install flask flask-session
3. flask run

### Future plans
I want to add user login, maybe some basic machine learning for alerts, and keep learning more about cloud security and pentesting.

This project was really important for me because it connects my past job with where I want to go in cybersecurity. I hope you like it.

**Author**
Angel Alfonso Rodriguez Bolivar
Barranquilla, Colombia
March 2026
