# Let's Recon - Passive OSINT Aggregator & Security Dashboard

Let's Recon is a premium, real-time passive reconnaissance aggregator and target intelligence dashboard designed for security researchers and penetration testers. It streams discoveries (subdomains, DNS records, historical URLs, WHOIS records, GeoIP mappings, WAF signatures, and exposed leaks) from multiple threat intelligence APIs and local tools simultaneously over high-speed WebSockets and stores them in a local SQLite database for instant retrieval.

## 🚀 Key Features

- **Real-Time Streaming**: Uses WebSockets to push live logs and findings from sub-modules directly to the web dashboard without making you wait for the entire scan to finish.
- **Persistent Scan History**: Integrates a local SQLite backend to automatically cache all target discoveries. Use the interactive left sidebar to view, search, and reload previous scan details instantly.
- **Optimized Wayback Machine Lookup**: Powered by optimized CDX queries (`matchType=domain`) to avoid server-side timeouts and blocks, retrieving historical web paths in under 2 seconds.
- **Firewall & WAF Detection**: Scans target hostnames to identify web application firewalls, vendor names, and manufacturing info.
- **Passive DNS & Certificate Transparency**: Queries certificate logs and passive DNS records to map subdomains, MX/TXT/A/NS records, and server locations.
- **Glassmorphism UI**: Beautiful, premium dark-themed dashboard styled with Tailwind CSS, metric progress bars, and custom terminal logs.

---

## 🛠️ Prerequisites

- **Python**: Version 3.8 or higher.
- **Operating System**: Linux (recommended) or macOS.

---

## 📥 Installation & Setup

Follow these steps to set up the tool on your laptop:

### 1. Clone the Repository
Clone your repository from GitHub and navigate to the project directory:
```bash
git clone https://github.com/your-username/letsrecon.git
cd letsrecon
```

### 2. Set Up a Virtual Environment (Recommended)
Create and activate a Python virtual environment to keep your global packages clean:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
Install all the required Python packages:
```bash
pip install -r requirements.txt
```

---

## ⚡ How to Run the Tool

Launch the FastAPI backend server:
```bash
python3 app.py
```

This will automatically:
1. Initialize the SQLite scan history database (`recon_history.db`).
2. Start the Uvicorn server on `http://localhost:8000`.
3. Open your default web browser to the dashboard automatically.

*If it does not open automatically, visit **[http://localhost:8000](http://localhost:8000)** in your browser.*

---

## 📖 Usage Guide

1. **Start a New Scan**:
   - Enter your target domain (e.g., `example.com`) or IP address in the target input field.
   - Click the **Start Scanning** button or press `Enter`.
   - Watch the live system console log module progress, and check the metric cards as data is populated in real-time.

2. **Access History**:
   - Locate the **Scan History** sidebar on the left.
   - Click on any previous target to instantly load and display all cached findings without re-running active network requests.
   - Use the **Search targets...** bar to filter your past targets.
   - Hover over any history item and click the trash can icon to delete that scan record permanently.

3. **Export Findings**:
   - Head to the **Subdomains** or **Wayback URLs** tabs.
   - Click **Export CSV** to download the tabular discoveries directly to your machine.

---

## ⚙️ Project Structure

```text
letsrecon/
│
├── app.py                # FastAPI web server, WebSocket handlers & SQLite database controller
├── requirements.txt      # Python package dependencies
├── README.md             # Project documentation (this file)
├── .gitignore            # Git exclusion rules (ignores local databases & caches)
│
└── templates/
    └── index.html        # Front-end UI (Tailwind CSS, charts & WebSockets logic)
```
