from __future__ import annotations

from functools import lru_cache

from fastembed import SparseTextEmbedding, TextEmbedding
from qdrant_client import models

from .settings import DENSE_MODEL, SPARSE_MODEL


@lru_cache
def dense_model() -> TextEmbedding:
    return TextEmbedding(DENSE_MODEL)


@lru_cache
def sparse_model() -> SparseTextEmbedding:
    return SparseTextEmbedding(SPARSE_MODEL)


def dense(texts: list[str], batch_size: int = 64) -> list[list[float]]:
    return [v.tolist() for v in dense_model().embed(texts, batch_size=batch_size)]


def sparse(texts: list[str]) -> list[models.SparseVector]:
    return [models.SparseVector(indices=v.indices.tolist(), values=v.values.tolist())
            for v in sparse_model().embed(texts)]


def sparse_query(text: str) -> models.SparseVector:
    v = next(iter(sparse_model().query_embed(text)))
    return models.SparseVector(indices=v.indices.tolist(), values=v.values.tolist())
