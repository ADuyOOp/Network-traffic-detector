import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import time
import os
from datetime import datetime

# Configure page
st.set_page_config(page_title="Network Traffic Anomaly Detection", layout="wide")
st.title("Network Traffic Anomaly Detection")

# Function to load data from CSV
def load_data(file_path):
    try:
        # Check if file_path is a string (path) or a file-like object (from uploader)
        if isinstance(file_path, str):
            df = pd.read_csv(file_path)
        else:
            df = pd.read_csv(file_path)

        # Convert timestamp to datetime if it exists
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"Error loading data: {str(e)}")
        return None

# Function to preprocess data for anomaly detection
def preprocess_data(df):
    # Select numerical features for anomaly detection
    numerical_features = ['size', 'src_port', 'dst_port', 'time_relative']

    # Create a copy of the dataframe with only numerical features
    df_numerical = df[numerical_features].copy()

    # Handle missing values
    df_numerical = df_numerical.fillna(0)

    # Convert protocol to numerical using one-hot encoding if available
    if 'protocol' in df.columns:
        protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
        df_numerical = pd.concat([df_numerical, protocol_dummies], axis=1)

    return df_numerical

# Function to detect anomalies using Isolation Forest
def detect_anomalies(df_numerical, contamination=0.05):
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
    # Combine original dataframe with anomaly results
    df_result = df.copy()
    df_result['anomaly'] = df_with_anomalies['anomaly']

    # Create visualizations
    st.subheader("Anomaly Detection Results")

    # Display metrics
    col1, col2 = st.columns(2)
    with col1:
        total_packets = len(df_result)
        st.metric("Total Packets", total_packets)
    with col2:
        anomaly_count = df_result['anomaly'].sum()
        st.metric("Anomalies Detected", f"{anomaly_count} ({(anomaly_count/total_packets)*100:.2f}%)")

    # Get anomalies with explanations
    anomalies_with_explanations = explain_anomalies(df, df_with_anomalies, scaler, model)

    # Display the anomalous packets with explanations
    st.subheader("Anomalous Packets with Explanations")

    if len(anomalies_with_explanations) > 0:
        # Select columns to display
        display_columns = [
            "timestamp", "source", "destination", "protocol",
            "size", "src_port", "dst_port", "explanation"
        ]
        # Filter to only include columns that exist in the dataframe
        display_columns = [col for col in display_columns if col in anomalies_with_explanations.columns]

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
        st.info("No anomalies detected in the dataset.")

# Main function
def main():
    # Sidebar for configuration
    st.sidebar.title("Configuration")

    # Data source selection
    st.sidebar.subheader("Data Source")
    data_source = st.sidebar.radio(
        "Select data source",
        ["Upload CSV", "Use Sample Data"]
    )

    # Initialize df as None
    df = None

    # Handle data source selection
    if data_source == "Upload CSV":
        uploaded_file = st.sidebar.file_uploader("Upload CSV file", type=["csv"])
        if uploaded_file is not None:
            try:
                df = load_data(uploaded_file)
                st.sidebar.success("File uploaded successfully!")
            except Exception as e:
                st.sidebar.error(f"Error loading uploaded file: {str(e)}")
    else:
        # Use sample data
        sample_file_path = "sample_network_data.csv"

        # Check if the sample file exists
        if not os.path.exists(sample_file_path):
            st.error(f"Sample file {sample_file_path} not found. Please make sure the file exists in the current directory.")
            return

        st.sidebar.success(f"Using data from {sample_file_path}")

        try:
            df = load_data(sample_file_path)
        except Exception as e:
            st.sidebar.error(f"Error loading sample file: {str(e)}")

    # Anomaly detection parameters
    contamination = st.sidebar.slider(
        "Contamination (expected proportion of anomalies)",
        min_value=0.01,
        max_value=0.5,
        value=0.05,
        step=0.01
    )

    # Process data if available
    if df is None:
        if data_source == "Upload CSV":
            st.info("Please upload a CSV file to begin analysis.")

            # Show expected CSV format
            st.subheader("Expected CSV Format")
            example_data = {
                "timestamp": ["2023-01-01 12:00:00", "2023-01-01 12:00:01"],
                "source": ["192.168.1.1", "192.168.1.2"],
                "source_domain": ["device1.local", "device2.local"],
                "destination": ["8.8.8.8", "1.1.1.1"],
                "destination_domain": ["dns.google", "cloudflare-dns.com"],
                "protocol": ["TCP", "UDP"],
                "size": [64, 128],
                "src_port": [12345, 54321],
                "dst_port": [443, 53],
                "tcp_flags": ["0x18", ""],
                "time_relative": [0.0, 1.0]
            }
            st.dataframe(pd.DataFrame(example_data), use_container_width=True)
        else:
            st.error("Could not load the sample data file.")
        return

    # Continue with data processing
    try:
        # Display all raw data with filtering options
        st.subheader("Complete Network Data")

        # Add filtering options
        with st.expander("Filter Data", expanded=False):
            col1, col2 = st.columns(2)

            # Protocol filter
            with col1:
                if 'protocol' in df.columns:
                    protocols = ['All'] + sorted(df['protocol'].unique().tolist())
                    selected_protocol = st.selectbox("Filter by Protocol", protocols)

            # Source IP filter
            with col2:
                if 'source' in df.columns:
                    sources = ['All'] + sorted(df['source'].unique().tolist())
                    selected_source = st.selectbox("Filter by Source IP", sources)

            # Search functionality
            search_term = st.text_input("Search in any field", "")

        # Apply filters
        filtered_df = df.copy()

        if 'protocol' in df.columns and selected_protocol != 'All':
            filtered_df = filtered_df[filtered_df['protocol'] == selected_protocol]

        if 'source' in df.columns and selected_source != 'All':
            filtered_df = filtered_df[filtered_df['source'] == selected_source]

        # Apply search across all string columns
        if search_term:
            mask = pd.Series(False, index=filtered_df.index)
            for col in filtered_df.select_dtypes(include=['object']).columns:
                mask = mask | filtered_df[col].astype(str).str.contains(search_term, case=False, na=False)
            filtered_df = filtered_df[mask]

        # Show the filtered data
        st.dataframe(filtered_df, use_container_width=True, height=400)

        # Show filter summary
        st.caption(f"Showing {len(filtered_df)} of {len(df)} records")

        # Display data statistics
        st.subheader("Data Statistics")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Packets", len(df))
        with col2:
            if 'protocol' in df.columns:
                protocols = df['protocol'].value_counts()
                st.metric("Protocols", len(protocols))
        with col3:
            if 'source' in df.columns:
                sources = df['source'].nunique()
                st.metric("Unique Sources", sources)

        # Preprocess data
        df_numerical = preprocess_data(df)

        # Detect anomalies
        df_with_anomalies, model, scaler = detect_anomalies(df_numerical, contamination)

        # Display anomalies with explanations
        display_anomalies(df, df_with_anomalies, scaler, model)
    except Exception as e:
        st.error(f"Error processing data: {str(e)}")
        st.exception(e)

if __name__ == "__main__":
    main()
