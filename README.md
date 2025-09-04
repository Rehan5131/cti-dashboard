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

### 1. Clone the Repository###
```bash
git clone https://github.com/your-username/cti-dashboard.git
cd cti-dashboard

### 2. Clone the Repository### 
```bash
python -m venv venv
source venv/bin/activate   # On Linux/Mac
venv\Scripts\activate      # On Windows

### 3. Install Requirements### 
```bash
pip install -r requirements.txt

### 4. Configure Environment Variables### 
#Create a .env file in the root folder:#
```bash
SECRET_KEY=your-secret-key
MONGO_URI=mongodb://localhost:27017/ctidb
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
INGEST_INTERVAL_MIN=10

### Run the App### 
```bash
python app.py

### 2. Clone the Repository### 
```bash

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

## ⚠️ Notes
- Free API keys (VirusTotal/AbuseIPDB) may have rate limits.
- Charts update when ingestion runs (INGEST_INTERVAL_MIN).
- Use MongoDB Compass to explore stored IOCs and metrics.