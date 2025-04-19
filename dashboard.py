import streamlit as st
import pandas as pd
import plotly.express as px
import threading
import time
import queue
from datetime import datetime
import logging
from scapy.all import sniff, IP, TCP, UDP
import platform
import socket
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_batch

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Database Configuration
DB_CONFIG = {
    'dbname': 'network_traffic',
    'user': 'postgres',
    'password': '123456',
    'host': 'localhost',
    'port': '5432'
}

class DatabaseManager:
    """Handles all database operations"""
    
    def __init__(self):
        self.conn = None
        self.connect()
        self.create_table()
        
    def connect(self):
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            logger.info("Connected to PostgreSQL database")
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            raise
            
    def create_table(self):
        """Create the packets table if it doesn't exist"""
        create_table_query = """
        CREATE TABLE IF NOT EXISTS packets (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            source_ip VARCHAR(45),
            source_domain VARCHAR(255),
            destination_ip VARCHAR(45),
            destination_domain VARCHAR(255),
            protocol VARCHAR(10),
            size INTEGER,
            src_port INTEGER,
            dst_port INTEGER,
            tcp_flags VARCHAR(10),
            time_relative FLOAT
        );
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(create_table_query)
                self.conn.commit()
        except Exception as e:
            logger.error(f"Error creating table: {str(e)}")
            self.conn.rollback()
            raise
            
    def insert_packet(self, packet_info):
        """Insert a single packet into the database"""
        insert_query = """
        INSERT INTO packets (
            timestamp, source_ip, source_domain, destination_ip, destination_domain,
            protocol, size, src_port, dst_port, tcp_flags, time_relative
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(insert_query, (
                    packet_info['timestamp'],
                    packet_info['source'],
                    packet_info['source_domain'],
                    packet_info['destination'],
                    packet_info['destination_domain'],
                    packet_info['protocol'],
                    packet_info['size'],
                    packet_info.get('src_port'),
                    packet_info.get('dst_port'),
                    packet_info.get('tcp_flags'),
                    packet_info['time_relative']
                ))
                self.conn.commit()
        except Exception as e:
            logger.error(f"Error inserting packet: {str(e)}")
            self.conn.rollback()
            raise
            
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self, db_manager):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.packet_data = queue.Queue(maxsize=10000)
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.db_manager = db_manager

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to readable protocol name"""
        return self.protocol_map.get(protocol_num, f"OTHER({protocol_num})")

    def resolve_ip_to_domain(self, ip_address: str) -> str:
        """Resolve an IP address to a domain name (if possible)"""
        try:
            domain = socket.gethostbyaddr(ip_address)[0]
            return domain
        except (socket.herror, socket.gaierror):
            return ip_address

    def process_packet(self, packet) -> None:
        """Process an incoming network packet and extract relevant details"""
        try:
            if IP in packet:
                source_domain = self.resolve_ip_to_domain(packet[IP].src)
                destination_domain = self.resolve_ip_to_domain(packet[IP].dst)

                packet_info = {
                    "timestamp": datetime.now(),
                    "source": packet[IP].src,
                    "source_domain": source_domain,
                    "destination": packet[IP].dst,
                    "destination_domain": destination_domain,
                    "protocol": self.get_protocol_name(packet[IP].proto),
                    "size": len(packet),
                    "time_relative": (datetime.now() - self.start_time).total_seconds(),
                }

                if TCP in packet:
                    packet_info.update({
                        "src_port": packet[TCP].sport,
                        "dst_port": packet[TCP].dport,
                        "tcp_flags": str(packet[TCP].flags)
                    })
                elif UDP in packet:
                    packet_info.update({
                        "src_port": packet[UDP].sport,
                        "dst_port": packet[UDP].dport
                    })

                # Store in database
                self.db_manager.insert_packet(packet_info)
                
                # Also add to queue for real-time display
                if self.packet_data.full():
                    self.packet_data.get()
                self.packet_data.put(packet_info)
                
                logger.info(f"Captured and stored packet: {packet_info}")

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data queue to a pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(list(self.packet_data.queue))

def start_packet_capture(db_manager):
    """Start real-time packet capture in a separate thread"""
    processor = PacketProcessor(db_manager)

    def capture_packets():
        try:
            interface = "Wi-Fi" if "Windows" in str(platform.system()) else "wlan0"
            logger.info(f"Starting packet capture on interface: {interface}")
            sniff(prn=processor.process_packet, store=False, iface=interface)
        except Exception as e:
            logger.error(f"Failed to start packet capture: {str(e)}")

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    return processor

def create_visualizations(df: pd.DataFrame):
    """Generate data visualizations"""
    if len(df) > 0:
        df = df.copy()
        
        # Protocol distribution
        protocol_counts = df["protocol"].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values, names=protocol_counts.index, 
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df_grouped = df.groupby(df["timestamp"].dt.floor("s")).size()
        fig_timeline = px.line(
            x=df_grouped.index, y=df_grouped.values, 
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df["source"].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index, y=top_sources.values, 
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)

def main():
    """Main Streamlit Dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Initialize database manager
    if "db_manager" not in st.session_state:
        st.session_state.db_manager = DatabaseManager()

    # Initialize packet processor if not already in session state
    if "processor" not in st.session_state:
        st.session_state.processor = start_packet_capture(st.session_state.db_manager)
        st.session_state.start_time = time.time()
        st.session_state.all_packets = pd.DataFrame()

    # Retrieve the latest captured data
    new_packets = st.session_state.processor.get_dataframe()

    # Append new packets to the existing data
    if not new_packets.empty:
        st.session_state.all_packets = pd.concat(
            [st.session_state.all_packets, new_packets], 
            ignore_index=True
        )

    # Display metrics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Packets", len(st.session_state.all_packets))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(st.session_state.all_packets)

    # Show the most recent packets with scrollable table
    st.subheader("Recent Packets")
    if len(st.session_state.all_packets) > 0:
        st.dataframe(
            st.session_state.all_packets[
                ["timestamp", "source", "source_domain", "destination", 
                 "destination_domain", "protocol", "size"]
            ],
            use_container_width=True,
            height=400
        )

    # Automatic refresh every 5 seconds
    time.sleep(5)
    st.rerun()

if __name__ == "__main__":
    main()