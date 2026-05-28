# RAMDetect

RAMDetect is an academic Final Year Project titled:

**RAMDetect: A Machine Learning-Based RAM Forensics Analysis for Post-Incident**

RAMDetect is a post-incident RAM forensics triage tool. It supports RAM dump acquisition/import, memory artifact extraction, feature mapping, machine learning classification, report generation, activity logging, admin monitoring, and PTM central report repository integration.

## Repository Structure

client/  
RAMDetect client/admin application source and installer scripts.

ptm\_server/  
PTM Repository Server source package.

docs/  
Analyst/Admin deployment guides.

## Deployment Outputs

The final deployment package is generated separately and contains:

RAMDetect\_Analyst\_Setup.exe  
RAMDetect\_Admin\_Setup.exe  
RAMDetect\_PTM\_Server.zip  
README\_ANALYST\_DEPLOYMENT.md  
README\_ADMIN\_DEPLOYMENT.md

Installer and zip release files are not committed into the repository by default.

## PTM Repository Runtime Storage

The PTM server uses a separate runtime repository folder:

RAMDetect\_PTM\_ReportRepository/

This folder stores repository.db and uploaded report files. Admin workstations download reports through the PTM Repository API. The Admin workstation does not need a local copy of this folder.

Do not commit RAMDetect\_PTM\_ReportRepository into GitHub because it contains runtime data, uploaded reports, and repository database files.

## Security Notes

Do not commit real tokens, passwords, RAM dumps, generated reports, repository databases, or runtime environment files.

Do not commit:

RAMDETECT\_REPOSITORY\_API\_TOKEN  
RAMDETECT\_REPOSITORY\_ADMIN\_API\_TOKEN  
RAMDETECT\_DB\_URL with real password  
RAMDetect\_RUNTIME.env  
repository.db  
dumps/  
reports/  
logs/

If a real token is exposed, regenerate it before final deployment or demonstration.

## ML Design Rule

The final RAMDetect verdict is ML-only. RAMDetect uses 54 CIC-MalMem canonical features plus Autoencoder MSE as a fused Random Forest input. Native artifacts are used for report explanation and analyst interpretation, not deterministic verdict override.



