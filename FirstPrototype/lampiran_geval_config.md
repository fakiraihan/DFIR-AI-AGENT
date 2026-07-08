# Lampiran — Konfigurasi G-Eval (Final)

Sumber: [`eval/geval/metrics.py`](eval/geval/metrics.py), diimpor langsung oleh `eval/geval/runner.py`
(`from metrics import THRESHOLD, build_metrics`) yang menghasilkan
[`eval/geval/results/EVALUATION_REPORT.md`](eval/geval/results/EVALUATION_REPORT.md) — run 10 kasus
component-level pada dataset EVTX-Attack-Samples.

`judge_model` pada tiap `GEval()` di bawah adalah objek yang dikembalikan oleh
`build_judge_model()` (`evaluation/report_geval_evtx_runner.py`), yang membaca
`OPENAI_MODEL_NAME` dari `evaluation/.env`. Nilai yang benar-benar dipanggil pada
run terakhir adalah **`openai/gpt-5.4`** (endpoint KoboILM, OpenAI-compatible),
bukan `gpt-4o`. Nilai ini juga tercatat langsung pada payload hasil run
(`"judge_model": "openai/gpt-5.4"`).

`THRESHOLD = 0.70` didefinisikan sebagai konstanta modul dan direferensikan oleh
keempat dimensi.

---

## Dimensi 1: Accuracy

```python
accuracy = GEval(
    name="Accuracy",
    criteria=(
        "Tentukan apakah setiap klaim faktual dalam laporan investigasi "
        "didukung secara eksplisit oleh evidence yang tersedia pada konteks "
        "InvestigationState. Klaim yang tidak memiliki dukungan evidence "
        "dianggap fabrikasi dan diberi penalti berat."
    ),
    evaluation_steps=[
        "Identifikasi setiap klaim faktual pada laporan, termasuk klaim "
        "tentang IOC, attribusi ancaman, dampak insiden, dan tindakan "
        "respons yang direkomendasikan.",
        "Untuk setiap klaim, cari dukungan eksplisit pada evidence yang "
        "tersedia di konteks InvestigationState. Dukungan eksplisit "
        "berarti evidence menyebutkan fakta yang sama dengan klaim, "
        "bukan inferensi yang dibangun penilai sendiri.",
        "Hitung proporsi klaim yang memiliki dukungan eksplisit terhadap "
        "total klaim yang diidentifikasi.",
        "Berikan penalti berat untuk laporan yang memuat klaim spesifik "
        "(misalnya nilai threat_score, attribusi APT group, atau timestamp "
        "kejadian) yang tidak terdapat pada evidence.",
        "Panjang laporan tidak memengaruhi skor — laporan ringkas yang "
        "akurat lebih disukai daripada laporan panjang yang berulang "
        "atau mengembangkan klaim di luar evidence.",
    ],
    evaluation_params=[
        LLMTestCaseParams.INPUT,
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.CONTEXT,
    ],
    threshold=0.70,
    model=judge_model,
)
```

## Dimensi 2: Completeness

```python
completeness = GEval(
    name="Completeness",
    criteria=(
        "Tentukan apakah laporan investigasi mencantumkan seluruh "
        "Indicator of Compromise (IOC) yang relevan dari evidence, "
        "dengan klasifikasi tipe yang tepat dan tanpa duplikasi."
    ),
    evaluation_steps=[
        "Hitung jumlah IOC unik yang ada pada evidence di konteks "
        "InvestigationState (IP address, domain, URL, file hash, "
        "process name, registry path).",
        "Hitung jumlah IOC unik yang muncul pada laporan, dengan "
        "memperhatikan klasifikasi tipe (IP harus dilabel IP, hash "
        "harus dilabel hash, dst.).",
        "Hitung coverage = (IOC yang muncul pada laporan dan tipenya "
        "tepat) dibagi (total IOC unik pada evidence).",
        "Berikan penalti untuk IOC yang muncul pada laporan tetapi "
        "salah klasifikasi tipenya (misalnya URL dilabel sebagai "
        "domain).",
        "Berikan penalti untuk IOC duplikat yang muncul lebih dari "
        "sekali tanpa konteks yang berbeda.",
        "Tidak ada penalti untuk IOC tambahan yang muncul pada laporan "
        "tetapi tidak ada di evidence, selama IOC tersebut diturunkan "
        "secara wajar dari evidence (misalnya domain hasil parsing URL "
        "yang sudah ada di evidence).",
    ],
    evaluation_params=[
        LLMTestCaseParams.INPUT,
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.CONTEXT,
    ],
    threshold=0.70,
    model=judge_model,
)
```

## Dimensi 3: Timeline Coherence

```python
timeline_coherence = GEval(
    name="Timeline Coherence",
    criteria=(
        "Tentukan apakah urutan kronologis kejadian pada laporan "
        "investigasi konsisten dengan timestamp yang tercatat pada "
        "evidence, tanpa pembalikan urutan atau gap yang tidak "
        "dijustifikasi. Dimensi ini menilai konsistensi kronologis "
        "narasi, bukan kesegaran data (timeliness)."
    ),
    evaluation_steps=[
        "Ekstrak seluruh timestamp dan kejadian yang dirujuk pada "
        "evidence di konteks InvestigationState.",
        "Ekstrak urutan kejadian yang dipaparkan pada bagian timeline "
        "laporan.",
        "Bandingkan urutan kronologis pada laporan dengan urutan "
        "kronologis menurut timestamp evidence.",
        "Berikan penalti berat untuk pembalikan urutan (kejadian A "
        "dilaporkan sebelum kejadian B, padahal timestamp B mendahului A).",
        "Berikan penalti sedang untuk kejadian yang ada di evidence "
        "tetapi tidak dimasukkan pada timeline, terutama untuk kejadian "
        "yang memiliki signifikansi investigatif (misalnya initial access, "
        "lateral movement, exfiltration).",
        "Tidak ada penalti untuk pemadatan kejadian (mengelompokkan "
        "beberapa peristiwa yang dekat secara waktu) selama urutan "
        "kronologis tetap terjaga.",
    ],
    evaluation_params=[
        LLMTestCaseParams.INPUT,
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.CONTEXT,
    ],
    threshold=0.70,
    model=judge_model,
)
```

## Dimensi 4: Actionability

```python
actionability = GEval(
    name="Actionability",
    criteria=(
        "Tentukan apakah rekomendasi respons yang diberikan pada "
        "laporan spesifik, dapat dilaksanakan oleh analis SOC, "
        "dan terhubung dengan evidence yang konkret."
    ),
    evaluation_steps=[
        "Identifikasi seluruh rekomendasi respons yang tercantum pada "
        "laporan.",
        "Untuk setiap rekomendasi, periksa apakah merujuk pada evidence "
        "yang konkret (misalnya IP spesifik yang harus diblokir, hash "
        "file spesifik yang harus dikarantina, host spesifik yang harus "
        "diisolasi).",
        "Berikan penalti untuk rekomendasi generik yang tidak terhubung "
        "dengan temuan investigasi (misalnya 'tingkatkan kewaspadaan', "
        "'lakukan audit keamanan', 'edukasi pengguna').",
        "Berikan nilai lebih tinggi untuk rekomendasi yang memuat "
        "tindakan teknis spesifik (perintah firewall, IOC yang harus "
        "ditambahkan ke blocklist, registry key yang harus dipantau).",
        "Berikan nilai lebih tinggi untuk rekomendasi yang mengaitkan "
        "tindakan dengan tahap respons insiden (containment, eradication, "
        "recovery) sesuai NIST 800-61.",
        "Tidak ada penalti untuk rekomendasi yang singkat selama tetap "
        "spesifik dan actionable.",
    ],
    evaluation_params=[
        LLMTestCaseParams.INPUT,
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.CONTEXT,
    ],
    threshold=0.70,
    model=judge_model,
)
```

---

## Perbedaan dengan draf `eval_ulang_03_geval_report_quality.md`

| Aspek | Draf (`eval_ulang_03`, §3) | Kode final (`eval/geval/metrics.py`) | Signifikan? |
|---|---|---|---|
| Nama dimensi 1 | `Faithfulness` | `Accuracy` | Nama berubah; `criteria` dan `evaluation_steps` **identik kata per kata** |
| Nama dimensi 2 | `IOC Coverage` | `Completeness` | Nama berubah; `criteria` dan `evaluation_steps` **identik kata per kata** |
| Nama dimensi 3 | `Timeline Coherence` | `Timeline Coherence` | Sama, tapi lihat baris `criteria` di bawah |
| Nama dimensi 4 | `Recommendation Actionability` | `Actionability` | Nama berubah; `criteria` dan `evaluation_steps` **identik kata per kata** |
| `criteria` Timeline Coherence | Tanpa kalimat pembeda dari *timeliness* | Ditambah: *"Dimensi ini menilai konsistensi kronologis narasi, bukan kesegaran data (timeliness)."* | Ya — klarifikasi scope ditambahkan saat fix, kemungkinan untuk mencegah judge mencampur "urutan kronologis" dengan "kebaruan data" |
| `evaluation_steps` (semua 4 dimensi) | — | Identik dengan draf, tidak ada revisi step | Tidak ada perbedaan |
| `threshold` | `0.70` (semua dimensi) | `0.70` (via konstanta `THRESHOLD`) | Tidak ada perbedaan |
| `model` | Literal `"gpt-4o"` (placeholder, draf menyebutkan "GPT-4o atau GPT-5.4-class, pilih saat run-time") | `judge_model` — resolve ke **`openai/gpt-5.4`** (KoboILM) via `build_judge_model()` | Ya — draf masih ambigu antara gpt-4o/gpt-5.4; eksekusi final mengunci ke gpt-5.4, bukan gpt-4o |
| Cakupan evaluasi (di luar §3, lihat §1/§6 draf) | 30 kasus component-level + 10 kasus end-to-end (40 total) | Hanya **10 kasus**, seluruhnya component-level, dataset EVTX-Attack-Samples saja (lihat `EVALUATION_REPORT.md`) | Ya — cakupan run terakhir jauh lebih sempit dari rancangan awal; tidak ada evaluasi end-to-end maupun dataset lain yang tereksekusi |

**Kesimpulan:** rubrik penilaian (`criteria` + `evaluation_steps`) tidak berubah secara substantif dari draf — hanya nama tiga dari empat dimensi yang diringkas/diganti, dan `criteria` Timeline Coherence mendapat satu kalimat klarifikasi tambahan. Perbedaan yang lebih penting untuk dicatat di skripsi ada di luar `GEval()` itu sendiri: (1) model judge terkunci ke `openai/gpt-5.4`, bukan `gpt-4o` seperti opsi di draf; dan (2) cakupan evaluasi final yang benar-benar dieksekusi (10 kasus, component-level, EVTX-Attack-Samples) jauh lebih kecil dari rancangan 40-kasus component+end-to-end pada draf.
