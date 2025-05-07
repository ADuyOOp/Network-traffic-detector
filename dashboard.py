import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import threading
import time
import queue
from datetime import datetime
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
import platform
import socket
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_batch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

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
                elif ICMP in packet:
                    packet_info.update({
                        "src_port": 0,  # ICMP doesn't use ports, but we need values for anomaly detection
                        "dst_port": 0,
                        "icmp_type": packet[ICMP].type,
                        "icmp_code": packet[ICMP].code
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

# Function to preprocess data for anomaly detection
def preprocess_data(df):
    """Preprocess data for anomaly detection"""
    # Select numerical features for anomaly detection
    numerical_features = ['size', 'src_port', 'dst_port', 'time_relative']

    # Create a copy of the dataframe with only numerical features that exist
    available_features = [f for f in numerical_features if f in df.columns]
    df_numerical = df[available_features].copy()

    # Handle missing values
    df_numerical = df_numerical.fillna(0)

    # Convert protocol to numerical using one-hot encoding if available
    if 'protocol' in df.columns:
        protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
        df_numerical = pd.concat([df_numerical, protocol_dummies], axis=1)

    return df_numerical

# Function to detect anomalies using Isolation Forest
def detect_anomalies(df_numerical, contamination=0.05):
    """Detect anomalies in network traffic data"""
    # Check if we have enough data
    if len(df_numerical) < 10:  # Need at least 10 samples for meaningful anomaly detection
        return None, None, None

    # Scale the features
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df_numerical)

    # Apply Isolation Forest
    model = IsolationForest(contamination=contamination, random_state=42)
    df_numerical['anomaly'] = model.fit_predict(df_scaled)

    # Get anomaly scores (negative scores are more anomalous)
    df_numerical['anomaly_score'] = model.score_samples(df_scaled)

    # Convert predictions: -1 for anomalies, 1 for normal points
    # Convert to boolean for easier filtering: True for anomalies
    df_numerical['anomaly'] = df_numerical['anomaly'] == -1

    return df_numerical, model, scaler

# Function to explain why a packet is anomalous
def explain_anomalies(df, df_with_anomalies, scaler, model):
    """Generate explanations for why packets are flagged as anomalies"""
    # Combine original dataframe with anomaly results
    df_result = df.copy()
    df_result['anomaly'] = df_with_anomalies['anomaly']
    df_result['anomaly_score'] = df_with_anomalies['anomaly_score']

    # Get feature names used in the model
    feature_names = df_with_anomalies.columns.tolist()
    feature_names.remove('anomaly')
    feature_names.remove('anomaly_score')

    # Calculate normal ranges for each feature (using non-anomalous data)
    normal_data = df_with_anomalies[~df_with_anomalies['anomaly']]
    feature_stats = {}
    for feature in feature_names:
        if feature in normal_data.columns:
            # Check if the feature is boolean or binary (0/1)
            is_bool_or_binary = (
                normal_data[feature].dtype == bool or
                (normal_data[feature].isin([0, 1]).all() and len(normal_data[feature].unique()) <= 2)
            )

            if is_bool_or_binary:
                # For boolean/binary features, use simpler statistics
                feature_stats[feature] = {
                    'mean': normal_data[feature].mean(),
                    'std': normal_data[feature].std() if normal_data[feature].std() > 0 else 0.1,
                    'min': 0,
                    'max': 1,
                    'q1': 0,
                    'q3': 1,
                    'iqr': 1,
                    'lower_bound': 0,
                    'upper_bound': 1
                }
            else:
                # For numerical features, calculate quantiles
                feature_stats[feature] = {
                    'mean': normal_data[feature].mean(),
                    'std': normal_data[feature].std() if normal_data[feature].std() > 0 else 0.1,
                    'min': normal_data[feature].min(),
                    'max': normal_data[feature].max(),
                }

                # Only calculate quantiles for numeric data
                try:
                    feature_stats[feature]['q1'] = normal_data[feature].quantile(0.25)
                    feature_stats[feature]['q3'] = normal_data[feature].quantile(0.75)
                    # Calculate IQR (Interquartile Range)
                    feature_stats[feature]['iqr'] = feature_stats[feature]['q3'] - feature_stats[feature]['q1']
                    # Define normal range as Q1-1.5*IQR to Q3+1.5*IQR
                    feature_stats[feature]['lower_bound'] = feature_stats[feature]['q1'] - 1.5 * feature_stats[feature]['iqr']
                    feature_stats[feature]['upper_bound'] = feature_stats[feature]['q3'] + 1.5 * feature_stats[feature]['iqr']
                except (TypeError, ValueError):
                    # If quantiles fail, use min/max with a buffer
                    min_val = feature_stats[feature]['min']
                    max_val = feature_stats[feature]['max']
                    range_val = max_val - min_val if max_val > min_val else 1.0

                    feature_stats[feature]['q1'] = min_val
                    feature_stats[feature]['q3'] = max_val
                    feature_stats[feature]['iqr'] = range_val
                    feature_stats[feature]['lower_bound'] = min_val - 0.1 * range_val
                    feature_stats[feature]['upper_bound'] = max_val + 0.1 * range_val

    # Add explanation column to anomalies
    anomalies = df_result[df_result['anomaly'] == True].copy()

    if len(anomalies) > 0:
        explanations = []

        for idx, row in anomalies.iterrows():
            unusual_features = []

            # Check each feature to see if it's outside normal range
            for feature in feature_names:
                if feature in row and feature in feature_stats:
                    value = row[feature]
                    stats = feature_stats[feature]

                    # Check if the feature is boolean or binary
                    is_bool_or_binary = (
                        isinstance(value, bool) or
                        (isinstance(value, (int, float)) and value in [0, 1])
                    )

                    if is_bool_or_binary:
                        # For boolean features, only consider True (1) as unusual if it's rare
                        if value == 1 and stats['mean'] < 0.1:  # If True is rare (less than 10% occurrence)
                            display_name = feature
                            if feature.startswith('protocol_'):
                                display_name = feature[9:]  # Remove 'protocol_' prefix

                            unusual_features.append({
                                'feature': display_name,
                                'value': value,
                                'normal_range': "Mostly 0 (False)",
                                'direction': "high",
                                'severity': 1.0 / (stats['mean'] if stats['mean'] > 0 else 0.1)
                            })
                    else:
                        # For numerical features, check if outside normal range
                        if value < stats['lower_bound'] or value > stats['upper_bound']:
                            # Format the feature name for display
                            display_name = feature
                            if feature.startswith('protocol_'):
                                display_name = feature[9:]  # Remove 'protocol_' prefix

                            # Determine if it's unusually high or low
                            direction = "high" if value > stats['upper_bound'] else "low"

                            # Add to unusual features
                            unusual_features.append({
                                'feature': display_name,
                                'value': value,
                                'normal_range': f"{stats['lower_bound']:.2f} to {stats['upper_bound']:.2f}",
                                'direction': direction,
                                'severity': abs((value - stats['mean']) / (stats['std'] if stats['std'] > 0 else 1))
                            })

            # Sort unusual features by severity
            unusual_features.sort(key=lambda x: x['severity'], reverse=True)

            # Create explanation text
            if unusual_features:
                explanation_parts = []

                # Add specific explanations based on the data
                # Check for port scan pattern
                if 'dst_port' in row and row['protocol'] == 'TCP' and any(f['feature'] == 'dst_port' for f in unusual_features):
                    explanation_parts.append("Possible port scanning activity detected (multiple destination ports)")

                # Check for unusually large packet size
                if 'size' in row and any(f['feature'] == 'size' and f['direction'] == 'high' for f in unusual_features):
                    explanation_parts.append(f"Unusually large packet size ({row['size']} bytes)")

                # Check for unusual protocol
                if 'protocol' in row and row['protocol'] not in ['TCP', 'UDP']:
                    explanation_parts.append(f"Unusual protocol ({row['protocol']})")

                # Check for unusual port combinations
                if 'src_port' in row and 'dst_port' in row:
                    if row['dst_port'] in [4444, 1337, 31337, 8080]:
                        explanation_parts.append(f"Suspicious destination port ({row['dst_port']})")

                # Add general anomaly explanation based on unusual features
                for feature in unusual_features[:3]:  # Limit to top 3 most severe features
                    explanation_parts.append(
                        f"Unusual {feature['feature']} value: {feature['value']} "
                        f"({feature['direction']} - normal range: {feature['normal_range']})"
                    )

                explanation = " | ".join(explanation_parts)
            else:
                explanation = "Complex pattern anomaly detected by Isolation Forest algorithm"

            explanations.append(explanation)

        anomalies['explanation'] = explanations

        return anomalies
    else:
        return pd.DataFrame()

# Function to display anomalies with explanations
def display_anomalies(df, df_with_anomalies, scaler, model):
    """Display anomalies with explanations in the Streamlit UI"""
    # Combine original dataframe with anomaly results
    df_result = df.copy()
    df_result['anomaly'] = df_with_anomalies['anomaly']

    # Display metrics
    col1, col2 = st.columns(2)
    with col1:
        total_packets = len(df_result)
        st.metric("Total Packets Analyzed", total_packets)
    with col2:
        anomaly_count = df_result['anomaly'].sum()
        st.metric("Anomalies Detected", f"{anomaly_count} ({(anomaly_count/total_packets)*100:.2f}%)")

    # Get anomalies with explanations
    anomalies_with_explanations = explain_anomalies(df, df_with_anomalies, scaler, model)

    # Display the anomalous packets with explanations
    st.subheader("Anomalous Packets with Explanations")

    if len(anomalies_with_explanations) > 0:
        # Display each anomaly with its explanation
        for i, (idx, row) in enumerate(anomalies_with_explanations.iterrows()):
            with st.expander(f"Anomaly #{i+1} - {row['timestamp'] if 'timestamp' in row else 'Unknown time'} - {row['protocol'] if 'protocol' in row else 'Unknown protocol'}"):
                # Create two columns
                col1, col2 = st.columns([1, 2])

                with col1:
                    # Display packet details
                    st.markdown("**Packet Details:**")
                    details = []
                    if 'source' in row:
                        details.append(f"**Source:** {row['source']}")
                    if 'source_domain' in row:
                        details.append(f"**Source Domain:** {row['source_domain']}")
                    if 'destination' in row:
                        details.append(f"**Destination:** {row['destination']}")
                    if 'destination_domain' in row:
                        details.append(f"**Destination Domain:** {row['destination_domain']}")
                    if 'protocol' in row:
                        details.append(f"**Protocol:** {row['protocol']}")
                    if 'size' in row:
                        details.append(f"**Size:** {row['size']} bytes")
                    if 'src_port' in row:
                        details.append(f"**Source Port:** {row['src_port']}")
                    if 'dst_port' in row:
                        details.append(f"**Destination Port:** {row['dst_port']}")

                    st.markdown("\n".join(details))

                with col2:
                    # Display explanation
                    st.markdown("**Why is this an anomaly?**")
                    st.markdown(f"{row['explanation']}")

                    # Add severity indicator based on anomaly score
                    if 'anomaly_score' in row:
                        severity = "High" if row['anomaly_score'] < -0.2 else "Medium" if row['anomaly_score'] < -0.1 else "Low"
                        st.markdown(f"**Severity:** {severity} (score: {row['anomaly_score']:.4f})")

                    # Add potential security implications
                    st.markdown("**Potential Security Implications:**")
                    if 'port scan' in row['explanation'].lower():
                        st.markdown("- Port scanning is often a reconnaissance technique used to identify open services")
                    if 'large packet' in row['explanation'].lower():
                        st.markdown("- Unusually large packets could indicate data exfiltration or a DoS attack")
                    if 'unusual protocol' in row['explanation'].lower():
                        st.markdown("- Unusual protocols may indicate attempts to bypass firewall rules")
                    if 'suspicious' in row['explanation'].lower() and 'port' in row['explanation'].lower():
                        st.markdown("- Suspicious ports may indicate communication with command and control servers")
    else:
        st.info("No anomalies detected in the current network traffic.")

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
        st.session_state.anomaly_detection_enabled = True
        st.session_state.contamination = 0.05

    # Sidebar for configuration
    st.sidebar.title("Configuration")

    # Anomaly detection settings
    st.sidebar.subheader("Anomaly Detection")
    st.session_state.anomaly_detection_enabled = st.sidebar.checkbox("Enable Anomaly Detection", value=st.session_state.anomaly_detection_enabled)

    if st.session_state.anomaly_detection_enabled:
        st.session_state.contamination = st.sidebar.slider(
            "Contamination (expected proportion of anomalies)",
            min_value=0.01,
            max_value=0.2,
            value=st.session_state.contamination,
            step=0.01
        )

    # Retrieve the latest captured data
    new_packets = st.session_state.processor.get_dataframe()

    # Append new packets to the existing data
    if not new_packets.empty:
        st.session_state.all_packets = pd.concat(
            [st.session_state.all_packets, new_packets],
            ignore_index=True
        )

    # Create tabs for different views
    tab1, tab2 = st.tabs(["Dashboard", "Anomaly Detection"])

    with tab1:
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

    with tab2:
        st.header("Network Traffic Anomaly Detection")

        if not st.session_state.anomaly_detection_enabled:
            st.warning("Anomaly detection is currently disabled. Enable it in the sidebar to detect unusual network traffic patterns.")
        elif len(st.session_state.all_packets) < 10:
            st.info("Collecting data... Need at least 10 packets for anomaly detection.")
        else:
            try:
                # Preprocess data for anomaly detection
                df_numerical = preprocess_data(st.session_state.all_packets)

                # Detect anomalies
                df_with_anomalies, model, scaler = detect_anomalies(df_numerical, st.session_state.contamination)

                if df_with_anomalies is not None:
                    # Display anomalies with explanations
                    display_anomalies(st.session_state.all_packets, df_with_anomalies, scaler, model)
                else:
                    st.info("Not enough data for meaningful anomaly detection yet.")
            except Exception as e:
                st.error(f"Error in anomaly detection: {str(e)}")
                st.exception(e)

    # Automatic refresh every 5 seconds
    time.sleep(5)
    st.rerun()

if __name__ == "__main__":
    main()