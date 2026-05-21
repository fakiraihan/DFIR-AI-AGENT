# Optimasi dan Perbaikan Tool Call AI Agent DFIR

Saat ini, performa agen AI sangat lambat ketika melakukan pemanggilan API Threat Intelligence. Selain itu, **hanya VirusTotal yang berhasil mengembalikan data**, sementara API lain (ThreatFox, AlienVault OTX, GreyNoise, dll) seolah-olah "error" atau tidak menghasilkan apa-apa.

Berdasarkan investigasi mendalam ke dalam _source code_ (`threat_intel.py`, `agent.py`, dan `report.py`), saya menemukan akar masalah mengapa API lain gagal:

1. **Crash Akibat Karakter Unicode (Windows)**: `threatfox_lookup` menggunakan perintah `print(f"\n  → ThreatFox API Call")` dan tanda centang/silang. Pada sistem Windows, karakter-karakter ini memicu `UnicodeEncodeError` (charmap codec), sehingga sebelum API dipanggil, fungsi ini sudah **crash/error**.
2. **Format Response yang Tidak Dikenali Agent**: Pada `agent.py`, sistem menganggap pemanggilan sukses jika terdapat field `result["data"]`. VirusTotal (dan MalwareBazaar) mengembalikan key `"data"`, namun API seperti AlienVault OTX dan GreyNoise mengembalikan strukturnya sendiri (contoh: `pulse_count`, `classification`). Akibatnya, `agent.py` menganggap "No data found" padahal API tersebut sukses.
3. **Sistem Sinkron/Berurutan**: Proses menunggu API ini dieksekusi satu persatu sehingga memakan waktu sangat lama (bisa 10 detik per API).

## Rencana Perbaikan (Proposed Changes)

---

### 1. Perbaikan Bug API & Format Response (`threat_intel.py`)
* Menghapus karakter unicode yang memicu *crash* di sistem Windows.
* Menstandarisasi format kembalian (*response*) untuk **semua** API agar selalu menyertakan key `"data"`, sehingga `agent.py` dan `report.py` dapat memvalidasi dan memproses datanya (seperti OTX, URLhaus, dan GreyNoise akan dimasukkan ke format "data").
* Menyertakan HTTP Error Code yang eksplisit di dictionary jika terjadi kegagalan (misalnya 404, 429, 401), sehingga LLM mengetahui detail error-nya.

### 2. Eksekusi Asinkron yang Cepat (`agent.py`)
* Mengubah `execute_tools` dari yang sebelumnya menggunakan *for-loop* sinkron menjadi menggunakan **`concurrent.futures.ThreadPoolExecutor`**.
* Seluruh API akan dipanggil secara **paralel**. Jika ada 5 IOC dan 3 API, total 15 pemanggilan akan dijalankan bersamaan. Waktu tunggu yang tadinya > 100 detik akan ditekan menjadi maksimal hanya selama waktu pemanggilan paling lama (~10 detik).
* Menambahkan *Timeout Handling* yang lebih solid di setiap pemanggilan API.

### 3. Mempertahankan Logika Agentic (Non-Linear)
* Hasil eksekusi asinkron (baik yang berisi `"data"` maupun yang berisi `"error": 404 Not Found`) tetap akan dilempar ke LangGraph State sebagai `tool_results`. 
* Node `tool_selector` dan LLM akan bisa merespons: *"Oh, ThreatFox 404 untuk IP ini, tapi AlienVault mengembalikan data"*, sehingga sifat AI yang adaptif tetap terjaga.

## User Review Required

> [!IMPORTANT]
> Mohon review rencana di atas. Perbaikan ini akan menyelesaikan masalah API yang selalu *error*/*crash*, sekaligus mengubah sistem agar berjalan paralel. Apakah Anda setuju dengan pendekatan ini, atau adakah API tambahan yang ingin difokuskan?

## Verification Plan

### Automated Tests
- Menjalankan skrip *scratch test* secara lokal untuk membuktikan bahwa kelima API (ThreatFox, MalwareBazaar, URLhaus, AlienVault OTX, GreyNoise, VirusTotal) kini mengembalikan `status: Success` dan field `data` yang tidak kosong.

### Manual Verification
- Melakukan pemanggilan *End-to-End* pada log yang memicu ekstraksi IOC, lalu memantau kecepatan (harus di bawah 15 detik untuk seluruh batch) dan membuktikan bahwa OTX, ThreatFox, dll muncul pada hasil report, tidak hanya VirusTotal.
