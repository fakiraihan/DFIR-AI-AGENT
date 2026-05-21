# DummyAnomaly Dataset

Dataset dummy kecil untuk eksperimen deteksi anomali berbasis log.

- `DummyAnomaly.log_structured.csv`: 40 baris log terstruktur dengan kolom `Label`.
- `anomaly_label.csv`: label tingkat sesi (`SessionId`) untuk pemisahan Normal/Anomaly.
- Jumlah sesi: 13 sesi.
- Sesi anomali: `sess_005` berupa brute-force login dan `sess_011` berupa gangguan database/payment.
- Jumlah baris log anomali: 9 dari 40 baris.

Label yang dipakai adalah `Normal` dan `Anomaly`, mengikuti pola dataset HDFS di folder ini.
