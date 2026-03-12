# Log-based Anomaly Detection with Deep Learning: DeepLog & LogAnomaly

**Abstract**: Software-intensive systems produce logs for troubleshooting purposes. Recently, many deep learning models
have been proposed to automatically detect system anomalies based on log data. This repository provides a focused 
implementation of two key unsupervised log-based anomaly detection methods: **DeepLog** and **LogAnomaly**.

## I. Implemented Models

| Model                        | Paper                                                                                                                                          |
|:-----------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| **Unsupervised**             |                                                                                                                                                |
| DeepLog (CCS '17)            | [DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning](https://dl.acm.org/doi/abs/10.1145/3133956.3134015)          |
| LogAnomaly (IJCAI '19)       | [LogAnomaly: Unsupervised Detection of Sequential and Quantitative Anomalies in Unstructured Logs](https://www.ijcai.org/proceedings/2019/658) |

### Model Details

#### DeepLog
DeepLog uses an LSTM network to model log sequences and predict the next log event. It works by:
- Learning normal system behavior from sequential log events
- Predicting the next log key given a history of past log keys
- Detecting anomalies when the actual log key deviates from top-k predictions
- Features: Sequential log event IDs

#### LogAnomaly  
LogAnomaly extends DeepLog by incorporating both sequential and quantitative information:
- Uses two parallel LSTM networks: one for semantic/sequential features, one for event count vectors
- Captures both the order of log events and their occurrence patterns
- Features: Sequential + Quantitative (event counts) or Semantic (word embeddings) + Quantitative
- More robust to variations in log event sequences

## II. Requirements

- Python 3
- NVIDIA GPU + CUDA cuDNN
- PyTorch

The required packages are listed in requirements.txt. Install:

```
pip install -r requirements.txt
```

## III. Usage

### 1. Data Preparation

Raw and preprocessed datasets (including parsed logs and their embeddings) are available
at https://zenodo.org/record/8115559.

#### 1.1. Datasets

We use datasets collected by LogPAI for evaluation. The datasets are available
at [loghub](https://github.com/logpai/loghub).
The details of datasets is shown as belows:

| **Dataset**  | **Size** | **# Logs** | **# Anomalies** | **Anomaly Ratio** |
|:-------------|:---------|:-----------|:----------------|:------------------|
| HDFS         | 1.5  GB  | 11,175,629 | 16,838          | 2.93%             |
| BGL          | 743 MB   | 4,747,963  | 348,460         | 7.34 %            |
| Thunderbird  | 1.4 GB   | 10,000,000 | 4,934           | 0.49%             |
| Spirit       | 1.4 GB   | 5,000,000  | 764,500         | 15.29%            |

#### 1.2. Parsing

We use log parsers from [logparser](https://github.com/logpai/logparser) to parse raw logs.
We use AEL, Spell, Drain, and IPLoM for our experiments.
The configuration for each parser used in our experiments can be found [here](docs/PARSING.md).

#### 1.3. Embedding
For a fair comparison, we use the same fastText-based embedding method for all models.
Use the following command to generate embeddings for log templates:

```shell
$ cd dataset

# download fastText word2vec model
$ wget https://dl.fbaipublicfiles.com/fasttext/vectors-english/crawl-300d-2M.vec.zip & unzip crawl-300d-2M.vec.zip

# generate embeddings for log templates
$ python generate_embeddings.py <dataset> <strategy>
# where <dataset> is one of {HDFS, BGL, Thunderbird, or Spirit}
# and <strategy> is one of {average or tfidf}
```

### 2. Training and Testing
#### 2.1. Configuration File
The configuration files used to set up the hyperparameters for training and testing can be found at `/config`.
Main parameters are described as follows:

- `data_dir`: the directory of the dataset
- `log_file`: the path to the log file
- `dataset_name`: the name of the dataset
- `grouping`: the type of log grouping technique (session or sliding)
- `session_level`: to grouping with sliding window by time or log entries (i.e., entry or minute)
- `window_size`: window size for sliding grouping
- `step_size`: step size for sliding grouping (if `step_size` = `window_size`, it is equivalent to fixed grouping)
- `is_chronological`: whether to use chronological order for train/test split (only apply for sliding grouping)
- `model_name`: the name of the model (DeepLog or LogAnomaly)
- `sequential`: whether to use sequential features (i.e., indexes of log templates) - required for DeepLog
- `quantitative`: whether to use quantitative features (i.e., event count vectors) - required for LogAnomaly
- `semantic`: whether to use semantic features (i.e., log template embeddings) - optional for LogAnomaly
- `embedding_dim`: the dimension of log template embeddings
- `embeddings`: the path to the json file for log template embeddings

Training parameters such as `batch_size`, `lr`, `max_epoch`, `optimizer`, etc. are also defined in the configuration files.

#### 2.2. To run the code

**DeepLog Example:**
```shell
python main_run.py --config_file config/deeplog.yaml
```

**LogAnomaly Example:**
```shell
python main_run.py --config_file config/loganomaly.yaml
```

To see all the options, run `python main_run.py -h`.

**Key Configuration Differences:**
- **DeepLog**: Set `sequential: true`, `quantitative: false`, `semantic: false`
- **LogAnomaly**: Set `quantitative: true`, and either `sequential: true` or `semantic: true` (or both)


### Citation

If you find the code and models useful for your research, please cite the following paper:

```
@inproceedings{le2022log,
  title={Log-based Anomaly Detection with Deep Learning: How Far Are We?},
  author={Le, Van-Hoang and Zhang, Hongyu},
  booktitle={2022 IEEE/ACM 43rd International Conference on Software Engineering (ICSE)},
  year={2022}
}
```
