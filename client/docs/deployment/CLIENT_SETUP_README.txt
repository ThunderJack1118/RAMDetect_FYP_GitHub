RAMDetect Client Setup

1. Install Python 3.10.x.

2. Extract this folder anywhere, for example:
   C:\RAMDetect_Client

3. Open PowerShell in this folder:
   cd C:\RAMDetect_Client

4. Create and activate virtual environment:
   py -3.10 -m venv venv
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\venv\Scripts\Activate.ps1

5. Install requirements:
   python -m pip install --upgrade pip
   pip install -r requirements.txt

6. Configure server connection:
   Edit and run setup_client_workstation.ps1:
   .\setup_client_workstation.ps1

   Analyst workstation should use CLIENT token only.
   Do not configure ADMIN token on analyst/client workstations.

7. Test online server connection:
   python -c "from sqlalchemy import create_engine; import os; e=create_engine(os.getenv('RAMDETECT_DB_URL')); print(e.connect().exec_driver_sql('SELECT 1').scalar())"
   Invoke-RestMethod http://<PTM_SERVER_IP>:8765/health

   Expected:
   1
   status: ok

8. Run RAMDetect:
   python main.py

9. Offline Local Mode behavior:
   If RAMDetect cannot connect to the PostgreSQL server during startup, it will open Offline Local Mode instead of closing.

   Offline Local Mode:
   - bypasses central login
   - opens as Local Analyst
   - allows local dump acquisition/import, analysis, artifact viewing, ML insights, and local report export
   - disables Admin Management, central Activity Monitor, PTM repository upload/download, and central activity sync

   This mode does not change the ML verdict logic. The final verdict remains ML-only with the fixed Random Forest threshold.

10. PTM/admin server note:
   On the server/admin workstation, RAMDetect may attempt to start the local PostgreSQL service automatically if it is stopped:
   postgresql-x64-18

   This requires PowerShell/RAMDetect to be run as Administrator. Recommended server setup:
   Set-Service postgresql-x64-18 -StartupType Automatic
   Start-Service postgresql-x64-18

11. If online connection fails with "no pg_hba.conf entry":
   Edit pg_hba.conf on the PostgreSQL server and add the client subnet, for example:
   host    ramdetect_db    ramdetect_app    192.168.1.0/24    scram-sha-256

   Then restart PostgreSQL:
   Restart-Service postgresql-x64-18
