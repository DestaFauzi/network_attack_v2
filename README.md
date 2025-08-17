# Network Intrusion Detection System (NIDS) with Random Forest

### Created by Desta Fauzi H

A machine learning-based network security system that detects and classifies network attacks using the Random Forest algorithm. This system offers two main analysis modes: PCAP file analysis and real-time network monitoring, providing comprehensive network traffic analysis and threat detection capabilities.

## Key Features

- **Dual Analysis Modes:**
  - PCAP File Analysis: Process and analyze pre-captured network traffic files
  - Live Network Monitoring: Real-time traffic analysis and threat detection
- **Random Forest-based Detection:**
  - Advanced feature extraction from network flows
  - Intelligent traffic classification
  - High accuracy attack detection
  - Anomaly identification

## System Architecture

The system is built using the following key components:

- **Web Interface (Flask)**

  - RESTful API endpoints for data processing
  - Interactive dashboard for visualization
  - Real-time traffic monitoring display

- **Core Components**

  - Network Traffic Capture Module
  - Feature Extraction Engine
  - Random Forest Classifier
  - Real-time Alert Generation System

- **Data Processing Pipeline**

  1. Traffic Capture/PCAP Input
  2. Packet Processing & Feature Extraction
  3. ML Model Analysis
  4. Threat Classification
  5. Real-time Alert Generation

- **Storage & Logging**
  - Traffic logs database
  - Alert history
  - System performance metrics
