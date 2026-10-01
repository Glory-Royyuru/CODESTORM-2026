"""Feature group E — trigram tool-transition surprise (plan §16).

Markov-style trigram model over tool names, fitted on benign trajectories only.
P(t_i | t_{i-2}, t_{i-1}) uses interpolated add-k smoothing with bigram / unigram back-off.
surprisal = -log P ; normalised to [0, 1] by the surprisal of an unseen tool.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

BOS = "<s>"
UNK = "<unk>"


class TrigramModel:
    def __init__(self, k: float = 0.1, lambdas: tuple[float, float, float] = (0.6, 0.3, 0.1)):
        self.k = k
        self.lambdas = lambdas
        self.tri: Counter = Counter()
        self.bi: Counter = Counter()
        self.uni: Counter = Counter()
        self.ctx2: Counter = Counter()
        self.ctx1: Counter = Counter()
        self.vocab: set[str] = set()
        self.total = 0
        self.max_surprisal = 1.0

    @staticmethod
    def _padded(tools: list[str]) -> list[str]:
        return [BOS, BOS] + list(tools)

    def fit(self, sequences: list[list[str]]) -> "TrigramModel":
        for seq in sequences:
            p = self._padded(seq)
            for i in range(2, len(p)):
                a, b, c = p[i - 2], p[i - 1], p[i]
                self.tri[(a, b, c)] += 1
                self.ctx2[(a, b)] += 1
                self.bi[(b, c)] += 1
                self.ctx1[b] += 1
                self.uni[c] += 1
                self.vocab.add(c)
                self.total += 1
        self.vocab.add(UNK)
        # Normaliser: the largest attainable surprisal = a never-seen tool after the most-observed contexts
        V, k = len(self.vocab), self.k
        l3, l2, l1 = self.lambdas
        p_min = (l3 * k / (max(self.ctx2.values(), default=0) + k * V)
                 + l2 * k / (max(self.ctx1.values(), default=0) + k * V)
                 + l1 * k / (self.total + k * V))
        self.max_surprisal = -math.log(p_min)
        return self

    def _prob(self, ctx: tuple[str, str], tool: str) -> float:
        V = len(self.vocab) or 1
        k = self.k
        a, b = ctx
        p3 = (self.tri.get((a, b, tool), 0) + k) / (self.ctx2.get((a, b), 0) + k * V)
        p2 = (self.bi.get((b, tool), 0) + k) / (self.ctx1.get(b, 0) + k * V)
        p1 = (self.uni.get(tool, 0) + k) / (self.total + k * V)
        l3, l2, l1 = self.lambdas
        return l3 * p3 + l2 * p2 + l1 * p1

    def surprisal(self, history: list[str], tool: str) -> float:
        """Raw surprisal (nats) of ``tool`` given the tool history of the session."""
        p = self._padded(history)
        return -math.log(self._prob((p[-2], p[-1]), tool))

    def normalized_surprisal(self, history: list[str], tool: str) -> float:
        return float(min(1.0, max(0.0, self.surprisal(history, tool) / self.max_surprisal)))

    def to_json(self) -> dict:
        return {
            "type": "trigram_interpolated_addk",
            "k": self.k,
            "lambdas": list(self.lambdas),
            "total": self.total,
            "max_surprisal": self.max_surprisal,
            "vocab": sorted(self.vocab),
            "tri": [[a, b, c, n] for (a, b, c), n in self.tri.items()],
            "bi": [[b, c, n] for (b, c), n in self.bi.items()],
            "uni": [[c, n] for c, n in self.uni.items()],
            "ctx2": [[a, b, n] for (a, b), n in self.ctx2.items()],
            "ctx1": [[b, n] for b, n in self.ctx1.items()],
        }

    @classmethod
    def from_json(cls, d: dict) -> "TrigramModel":
        m = cls(k=d["k"], lambdas=tuple(d["lambdas"]))
        m.total = d["total"]
        m.max_surprisal = d["max_surprisal"]
        m.vocab = set(d["vocab"])
        m.tri = Counter({(a, b, c): n for a, b, c, n in d["tri"]})
        m.bi = Counter({(b, c): n for b, c, n in d["bi"]})
        m.uni = Counter({c: n for c, n in d["uni"]})
        m.ctx2 = Counter({(a, b): n for a, b, n in d["ctx2"]})
        m.ctx1 = Counter({b: n for b, n in d["ctx1"]})
        return m

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.to_json()), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "TrigramModel":
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))
