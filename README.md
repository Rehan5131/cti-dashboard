# 🛡️ Cyber Threat Intelligence Dashboard

A web-based **Cyber Threat Intelligence (CTI) Dashboard** built with **Flask, MongoDB, and OSINT feeds**.  
It allows security analysts to **lookup, tag, store, and visualize IOCs (Indicators of Compromise)** with live data ingestion and analytics.

---

## 🚀 Features

- 🔍 **IOC Lookup** (IP, Domain, URL, Hash)  
  - Live checks against **VirusTotal** and **AbuseIPDB**  
  - Lookup history with export option  

- 🏷️ **IOC Tagging & Classification**  
  - Add IOC type and custom tags  
  - Stored in MongoDB for long-term analysis  

- 📊 **Dashboard & Analytics**  
  - IOC totals by type  
  - Daily ingestion trend chart  
  - Boxplot chart for IOC analysis  

- ⏱️ **Automated Data Ingestion**  
  - Background job fetches live OSINT feeds  
  - Updates metrics and IOC database  

- 📂 **Export Options**  
  - Export Lookup History as `.csv`  
  - Export all IOCs as `.csv`  

---

## 🛠️ Tech Stack

- **Backend:** Python (Flask), APScheduler  
- **Database:** MongoDB (via PyMongo)  
- **Frontend:** HTML + TailwindCSS + Jinja2  
- **Visualization:** Chart.js  
- **OSINT Sources:** VirusTotal API, AbuseIPDB API, custom feeds  

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/cti-dashboard.git
cd cti-dashboard
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate   # On Linux/Mac
venv\Scripts\activate      # On Windows
```

### 3. Install Requirements
```bash
pip install -r requirements.txt
```
### 4. Configure Environment Variables
*Create a .env file in the root folder:*
```bash
SECRET_KEY=your-secret-key
MONGO_URI=mongodb://localhost:27017/ctidb
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
INGEST_INTERVAL_MIN=10
```

### Run the App
```bash
python app.py
```

## Project Structure
```bash
cti-dashboard/
│── app.py                 # Main Flask app
│── requirements.txt
│── README.md
│── utils/
│   ├── db.py              # MongoDB collections
│   ├── helpers.py         # Timestamp helpers
│── collectors/
│   └── osint_feeds.py     # Ingestion sources
│── services/
│   ├── virustotal.py      # VT API integration
│   └── abuseipdb.py       # AbuseIPDB API integration
│── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── result.html
│   ├── charts.html
│   └── history.html
│── static/
│   └── css/ js/           # Tailwind + Chart.js
└── .env                   # API keys & configs
```

## ⚠️ Notes
- Free API keys (VirusTotal/AbuseIPDB) may have rate limits.
- Charts update when ingestion runs (INGEST_INTERVAL_MIN).
- Use MongoDB Compass to explore stored IOCs and metrics.

## 📊 Screenshots
*1. Dashboard*
<img width="1822" height="864" alt="Dashboard_1" src="https://github.com/user-attachments/assets/768ed68b-8a7f-4b89-9c26-7450ac367aa5" />

*2. Result*
<img width="1919" height="916" alt="Result_1" src="https://github.com/user-attachments/assets/57598473-f61b-4cbe-b4ea-2a2bdf36efca" />
<img width="1917" height="714" alt="Result_2" src="https://github.com/user-attachments/assets/6a763134-64b1-4385-bb44-46822350fdc1" />

*3. History*
<img width="1504" height="893" alt="History_1" src="https://github.com/user-attachments/assets/65d11ab1-447f-49fd-b9d3-82df9a8c3563" />

*4. Charts*
<img width="1697" height="891" alt="Charts_1" src="https://github.com/user-attachments/assets/a43be040-91fe-4c0f-9039-49f96b98e10d" />
<img width="1874" height="921" alt="Charts_2" src="https://github.com/user-attachments/assets/b60745be-fad3-4a9f-ac81-8350289c09d9" />
