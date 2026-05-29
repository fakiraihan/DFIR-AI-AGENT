import json
import pickle

from numpy import dot
from numpy.linalg import norm


def read_json(filename):
    with open(filename, "r") as load_f:
        file_dict = json.load(load_f)
    return file_dict


class Vocab(object):
    def __init__(self, logs, emb_file="embeddings.json", embedding_dim=100):
        self.stoi = {}
        self.pad_token = "padding"
        self.unk_token = "<UNK>"
        self.itos = [self.pad_token]

        for line in logs:
            self.itos.extend(line)
        self.mask_index = 4
        unique_events = list(dict.fromkeys(self.itos))
        if self.unk_token not in unique_events:
            unique_events.append(self.unk_token)
        self.itos = unique_events
        self.stoi = {e: i for i, e in enumerate(self.itos)}
        self.unk_index = self.stoi[self.unk_token]
        self.semantic_vectors = read_json(emb_file)
        self.semantic_vectors = {
            k: v if type(v) is list else [0] * embedding_dim
            for k, v in self.semantic_vectors.items()
        }
        self.semantic_vectors[self.pad_token] = [-1] * embedding_dim
        self.semantic_vectors[self.unk_token] = [0] * embedding_dim
        self.mapping = {}

    def __len__(self):
        return len(self.itos)

    def get_event(self, real_event, use_similar=False):
        event = self.stoi.get(real_event, self.unk_index)
        if not use_similar or event != self.unk_index:
            return event
        if self.mapping.get(real_event) is not None:
            return self.mapping[real_event]

        for train_event in self.itos[:-1]:
            sim = dot(
                self.semantic_vectors[real_event],
                self.semantic_vectors[train_event],
            ) / (
                norm(self.semantic_vectors[real_event])
                * norm(self.semantic_vectors[train_event])
            )
            if sim > 0.90:
                self.mapping[real_event] = self.stoi.get(train_event)
                return self.stoi.get(train_event)
        self.mapping[real_event] = self.unk_index
        return self.mapping[real_event]

    def get_embedding(self, event):
        return self.semantic_vectors[event]

    def save_vocab(self, file_path):
        with open(file_path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load_vocab(file_path):
        with open(file_path, "rb") as f:
            return pickle.load(f)
