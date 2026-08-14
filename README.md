# 🛡️ AI Network Anomaly Detection System

An interactive Machine Learning-based cybersecurity tool that analyzes network traffic metrics to detect anomalies and potential security threats. Built using Python, Scikit-Learn, and Tkinter.

---

## 📌 Project Overview
This project simulates an **Intrusion Detection & Traffic Analysis System** utilizing an **Unsupervised Machine Learning model (Isolation Forest)**. It allows security analysts to input custom packet metrics—such as **Packet Duration** and **Packet Size**—to evaluate whether traffic patterns align with expected baseline behavior or represent malicious anomalies.

---

## ✨ Key Features
* **Machine Learning Engine:** Implements Scikit-Learn's `IsolationForest` algorithm to isolate structural outliers in network metrics.
* **Interactive Graphical User Interface (GUI):** A dark-themed desktop application built with `Tkinter` for entering packet parameters and visualizing dynamic security alerts.
* **Audit Logging:** Automatically captures and stores analyzed packet entries into a `traffic_audit_log.csv` file for forensic review.
* **Instant Threat Classification:** Prompts alerts depending on whether traffic is classified as **Normal Traffic** or a **Threat/Anomaly**.

---

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Machine Learning:** Scikit-Learn (`IsolationForest`)
* **Data Handling:** Pandas, NumPy
* **GUI Framework:** Tkinter

---

## 🚀 How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/AI-Network-Anomaly-Detection.git](https://github.com/YOUR_USERNAME/AI-Network-Anomaly-Detection.git)
   pip install pandas scikit-learn numpy
   python app.py
