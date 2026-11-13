"""Strict precomputed type views. Scores are evidence for ranking, not solver facts."""

from dataclasses import dataclass
import hashlib
import json
import math


class TypeInformationUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class TypeView:
    labels: tuple[str, ...] = ()
    weights: tuple[float, ...] = ()
    source: str = "unavailable"
    artifact_sha256: str = ""
    model_sha256: str = ""
    raw_scores: tuple[float, ...] = ()

    @property
    def available(self):
        return bool(self.labels)

    def selector_features(self):
        """Keep candidate identity and scores; diversity is conditional on retained Top-K."""
        features = {"available": self.available, "candidate_count": len(self.labels),
                    "label_weights": {}, "raw_scores": {}, "conditional_entropy": None,
                    "candidate_disagreement": None, "raw_score_margin": None,
                    "weighting": "missing"}
        if not self.available:
            return features
        if not self.weights:
            features.update(label_weights={label: 1.0 for label in self.labels}, weighting="label_only")
            return features
        features.update(label_weights=dict(zip(self.labels, self.weights)),
                        raw_scores=dict(zip(self.labels, self.raw_scores)),
                        weighting="topk_conditional_softmax",
                        conditional_entropy=-sum(w * math.log(w) for w in self.weights if w > 0),
                        candidate_disagreement=max(0.0, 1.0 - sum(w * w for w in self.weights)))
        if len(self.raw_scores) >= 2:
            features["raw_score_margin"] = self.raw_scores[0] - self.raw_scores[1]
        return features

    def role_support(self, role):
        if not self.labels:
            return 0.0
        weights = self.weights or tuple(1.0 / len(self.labels) for _ in self.labels)
        def matches(label):
            lower = label.lower()
            pointer = "*" in lower or "ptr" in lower or "pointer" in lower or "array" in lower
            integer = (lower.startswith(("i", "u")) and any(c.isdigit() for c in lower)) or lower in ("int", "size_t", "char")
            return pointer if role == "pointer" else integer
        return sum(weight for label, weight in zip(self.labels, weights) if matches(label))


def load_type_view(path, query, variant, allow_synthetic=False):
    if variant in ("A", "B"):
        return TypeView()
    if path is None:
        raise TypeInformationUnavailable("Genuine mapped type candidates were not supplied")
    artifact_bytes = path.read_bytes()
    data = json.loads(artifact_bytes)
    if data.get("schema") != "symbai.mapped_types.v1":
        raise TypeInformationUnavailable("Unsupported type artifact schema")
    provenance = data.get("provenance", {})
    source = provenance.get("source")
    if source != "tygr_glowgnn" and not (allow_synthetic and source == "synthetic_test"):
        raise TypeInformationUnavailable("Type source is not genuine TYGR output")
    if source == "tygr_glowgnn" and not provenance.get("model_sha256"):
        raise TypeInformationUnavailable("Missing model identity")
    matches = [r for r in data.get("records", []) if r.get("use_site_id") == query.use_site_id]
    if len(matches) != 1:
        raise TypeInformationUnavailable("Use-site mapping is absent or ambiguous")
    record = matches[0]
    if record.get("binary_sha256") != query.binary_sha256:
        raise TypeInformationUnavailable("Candidate binary hash mismatch")
    if record.get("mapping_status") != "reviewed":
        raise TypeInformationUnavailable("Prediction/use-site mapping has not been reviewed")
    return project_type_candidates(record.get("candidates", []), record.get("score_kind"), variant,
                                   source, hashlib.sha256(artifact_bytes).hexdigest(),
                                   provenance.get("model_sha256", ""))


def project_type_candidates(candidates, score_kind, variant, source, artifact_sha256, model_sha256):
    """Project one prediction only. Callers validate its query/location provenance first."""
    if variant not in ("C", "D"):
        raise TypeInformationUnavailable("Candidate projection requires C or D")
    if not candidates or len({c["label"] for c in candidates}) != len(candidates):
        raise TypeInformationUnavailable("Missing or duplicate candidates")
    if [c.get("rank") for c in candidates] != list(range(1, len(candidates) + 1)):
        raise TypeInformationUnavailable("Candidate rank order is not explicit")
    if variant == "C":
        return TypeView((candidates[0]["label"],), (), source,
                        artifact_sha256, model_sha256)
    if len(candidates) < 2:
        raise TypeInformationUnavailable("D requires multiple actual candidates")
    if score_kind != "raw_logits":
        raise TypeInformationUnavailable("D currently accepts exported raw logits only")
    logits = [float(c["raw_score"]) for c in candidates]
    if not all(math.isfinite(v) for v in logits) or logits != sorted(logits, reverse=True):
        raise TypeInformationUnavailable("Invalid logits/ranking")
    # Conditional weighting within retained Top-K, not calibrated correctness probabilities.
    scale = max(logits)
    weights = [math.exp(v - scale) for v in logits]
    total = sum(weights)
    return TypeView(tuple(c["label"] for c in candidates),
                    tuple(v / total for v in weights), source,
                    artifact_sha256, model_sha256,
                    tuple(logits))
