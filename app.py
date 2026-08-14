import os
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, ttk
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class AnomalyDetectorApp:

  def __init__(self, root):
    self.root = root
    self.root.title("AI Network Threat & Anomaly Detector")
    self.root.geometry("520x620")
    self.root.configure(bg="#1e293b")  # Dark Theme

    # Heading
    title_label = tk.Label(
        root,
        text="🛡️ AI Network Anomaly Detector",
        font=("Segoe UI", 16, "bold"),
        bg="#1e293b",
        fg="#38bdf8",
    )
    title_label.pack(pady=15)

    sub_label = tk.Label(
        root,
        text="Machine Learning Based Network Traffic Analysis",
        font=("Segoe UI", 10),
        bg="#1e293b",
        fg="#94a3b8",
    )
    sub_label.pack(pady=(0, 15))

    # Train Isolation Forest Model
    # Baseline Normal Network Parameters [Duration (s), Packet Size (Bytes)]
    X_train = np.array([
        [0.05, 64],
        [0.10, 128],
        [0.12, 60],
        [0.08, 54],
        [0.20, 200],
        [0.18, 150],
        [0.05, 64],
        [0.11, 100],
        [0.15, 512],
        [0.25, 1024],
    ])

    self.model = IsolationForest(contamination=0.1, random_state=42)
    self.model.fit(X_train)

    # Frame for Inputs
    input_frame = tk.Frame(root, bg="#0f172a", padx=15, pady=15)
    input_frame.pack(pady=10, fill="x", padx=20)

    # Input 1: Packet Duration
    tk.Label(
        input_frame,
        text="Packet Duration (Seconds):",
        font=("Segoe UI", 10, "bold"),
        bg="#0f172a",
        fg="#f8fafc",
    ).pack(anchor="w", pady=(5, 2))
    self.entry_duration = tk.Entry(
        input_frame,
        font=("Segoe UI", 11),
        bg="#334155",
        fg="white",
        insertbackground="white",
    )
    self.entry_duration.pack(fill="x", pady=(0, 10))

    # Input 2: Packet Size
    tk.Label(
        input_frame,
        text="Packet Size (Bytes):",
        font=("Segoe UI", 10, "bold"),
        bg="#0f172a",
        fg="#f8fafc",
    ).pack(anchor="w", pady=(5, 2))
    self.entry_size = tk.Entry(
        input_frame,
        font=("Segoe UI", 11),
        bg="#334155",
        fg="white",
        insertbackground="white",
    )
    self.entry_size.pack(fill="x", pady=(0, 10))

    # Analyze Button
    btn_analyze = tk.Button(
        root,
        text="🔍 Analyze Traffic",
        command=self.predict,
        font=("Segoe UI", 11, "bold"),
        bg="#0284c7",
        fg="white",
        activebackground="#0369a1",
        activeforeground="white",
        pady=8,
        bd=0,
        cursor="hand2",
    )
    btn_analyze.pack(pady=15, fill="x", padx=20)

    # Log Table Section
    tk.Label(
        root,
        text="Analysis Audit Log:",
        font=("Segoe UI", 10, "bold"),
        bg="#1e293b",
        fg="#f8fafc",
    ).pack(anchor="w", padx=20)

    self.tree = ttk.Treeview(
        root,
        columns=("Time", "Duration", "Size", "Status"),
        show="headings",
        height=6,
    )
    self.tree.heading("Time", text="Time")
    self.tree.heading("Duration", text="Duration (s)")
    self.tree.heading("Size", text="Size (B)")
    self.tree.heading("Status", text="Status")

    self.tree.column("Time", width=90)
    self.tree.column("Duration", width=80)
    self.tree.column("Size", width=80)
    self.tree.column("Status", width=150)

    self.tree.pack(pady=10, fill="x", padx=20)

  def predict(self):
    try:
      duration = float(self.entry_duration.get())
      size = float(self.entry_size.get())

      # Model Prediction
      user_data = np.array([[duration, size]])
      prediction = self.model.predict(user_data)

      current_time = datetime.now().strftime("%H:%M:%S")

      if prediction[0] == -1:
        status = "⚠️ ANOMALY / THREAT"
        messagebox.showwarning(
            "Security Alert",
            f"⚠️ Threat Detected!\n\nDuration: {duration}s\nSize: {size} Bytes\n\nThis packet deviates significantly from normal baseline traffic.",
        )
      else:
        status = "✅ Normal Traffic"
        messagebox.showinfo(
            "Traffic Safe",
            f"✅ Traffic Normal\n\nDuration: {duration}s\nSize: {size} Bytes\n\nPattern matches expected baseline.",
        )

      # Log to Treeview UI
      self.tree.insert(
          "",
          0,
          values=(
              current_time,
              f"{duration}s",
              f"{size} B",
              status,
          ),
      )

      # Save to CSV log file
      self.save_to_log(current_time, duration, size, status)

    except ValueError:
      messagebox.showerror(
          "Input Error", "Please enter valid numeric values for packet fields."
      )

  def save_to_log(self, time_str, duration, size, status):
    log_file = "traffic_audit_log.csv"
    file_exists = os.path.exists(log_file)

    df = pd.DataFrame([{
        "Timestamp": time_str,
        "Duration_Sec": duration,
        "Packet_Size_Bytes": size,
        "Status": status,
    }])

    df.to_csv(log_file, mode="a", index=False, header=not file_exists)


if __name__ == "__main__":
  root = tk.Tk()
  app = AnomalyDetectorApp(root)
  root.mainloop()