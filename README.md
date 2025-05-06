
# Real-Time Network Traffic Analysis Dashboard

This project is a **Streamlit-based web application** for monitoring, analyzing, and visualizing real-time network traffic. It captures packets using Scapy, stores detailed information in a PostgreSQL database, and visualizes the data through interactive plots powered by Plotly.

## Features

-   Real-time packet capture using scapy
    
-   Domain resolution for source/destination IPs
    
-   Storage of detailed packet metadata in PostgreSQL
    
-   Interactive Streamlit dashboard with:
    
    -   Protocol distribution pie chart
        
    -   Packets per second line chart
        
    -   Top source IPs bar chart
        
    -   Scrollable table of recent packets
        
-   Automatic dashboard refresh every 5 seconds
    

## Technologies Used

-   Python
    
-   Streamlit
    
-   Scapy
    
-   Plotly
    
-   PostgreSQL
    
-   Pandas
    
-   Socket (for domain resolution)
    
-   Threading & Queue (for async packet processing)
    

## Requirements

-   Python 3.8+
    
-   PostgreSQL installed and running
    
-   Network interface (Wi-Fi or wlan0) permissions for packet sniffing
    
-   Admin/root privileges may be required to sniff network traffic
    

## Setup Instructions

### 1. Clone the Repository
    git clone https://github.com/ADuyOOp/Network-traffic-detector.git cd Network-traffic-detector

### 2. Install Dependencies

Create a virtual environment (optional but recommended):

    python -m venv venv

Activate the virtual environment:

-   On Linux/macOS: `source venv/bin/activate` 
-   On Windows: `venv\Scripts\activate` 

Install required libraries:

    pip install -r requirements.txt

If `requirements.txt` is not available, you can create it after installing all required packages:

    pip freeze > requirements.txt

Contents of `requirements.txt`:

    streamlit
    pandas
    plotly
    scapy
    psycopg2-binary

### 3. PostgreSQL Configuration

Make sure your PostgreSQL server is running and a database named `network_traffic` exists.

Create the database using terminal or pgAdmin:

    CREATE  DATABASE network_traffic;

Update database credentials in the `DB_CONFIG` variable in the Python code:

    `DB_CONFIG = { 'dbname': 'network_traffic', 'user': 'postgres', 'password': '123456', 'host': 'localhost', 'port': '5432' }

### 4. Run the Application

Start the Streamlit app:

    streamlit run app.py

_(Assuming the main file is named `app.py`. If it's different, update the filename accordingly.)_

### 5. View in Browser

Once running, open your browser and go to:

    http://localhost:8501

## Notes

-   This app captures packets on the interface named `Wi-Fi` (Windows) or `wlan0` (Linux).  
    You may need to change the interface name in the `start_packet_capture()` function.
    
-   Run the app with administrator or root privileges if needed to sniff packets.
    

## PostgreSQL Backup

To restore the database schema from a backup file named `network_traffic.sql`, use:

    psql -U postgres -d network_traffic -f network_traffic.sql

Replace `postgres` with your actual PostgreSQL username if different.

## Author

Tang Anh Duy  
[https://github.com/ADuyOOp/Network-traffic-detector.git](https://github.com/ADuyOOp/Network-traffic-detector.git)
