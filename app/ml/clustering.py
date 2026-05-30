"""
Log clustering using K-Means and DBSCAN algorithms.
"""
import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score
import joblib

from app.config import settings

logger = logging.getLogger(__name__)


class LogClustering:
    """Clustering analysis for log entries to find attack patterns."""
    
    def __init__(self, n_clusters: int = 5, algorithm: str = "kmeans"):
        self.n_clusters = n_clusters
        self.algorithm = algorithm
        self.model = None
        self.vectorizer = None
        self.is_fitted = False
        self.model_version = "1.0.0"
        self.labels = None
        self.cluster_summaries = {}
    
    def _extract_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """Extract TF-IDF features from logs."""
        texts = []
        for log in logs:
            # Combine relevant fields for clustering
            text_parts = [
                log.get("raw_log", ""),
                log.get("event_type", ""),
                log.get("source_type", ""),
                str(log.get("event_id", "")),
                log.get("severity", ""),
            ]
            texts.append(" ".join(text_parts))
        
        if self.vectorizer is None:
            self.vectorizer = TfidfVectorizer(
                max_features=200,
                ngram_range=(1, 3),
                min_df=1,
                max_df=0.9,
                stop_words="english",
            )
            features = self.vectorizer.fit_transform(texts).toarray()
        else:
            features = self.vectorizer.transform(texts).toarray()
        
        return features
    
    def fit(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the clustering model."""
        if len(logs) < 10:
            raise ValueError("Need at least 10 samples for clustering")
        
        logger.info(f"Training clustering model with {len(logs)} samples")
        
        # Extract features
        X = self._extract_features(logs)
        
        # Determine optimal clusters if not specified
        if self.n_clusters is None or self.n_clusters <= 0:
            self.n_clusters = min(10, max(2, len(logs) // 20))
        
        if self.algorithm == "kmeans":
            self.model = KMeans(
                n_clusters=self.n_clusters,
                random_state=42,
                n_init=10,
                max_iter=300,
            )
            self.labels = self.model.fit_predict(X)
        elif self.algorithm == "dbscan":
            self.model = DBSCAN(eps=0.5, min_samples=5, metric="cosine")
            self.labels = self.model.fit_predict(X)
            self.n_clusters = len(set(self.labels)) - (1 if -1 in self.labels else 0)
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")
        
        self.is_fitted = True
        self.model_version = f"1.0.{int(datetime.utcnow().timestamp())}"
        
        # Calculate silhouette score
        try:
            if len(set(self.labels)) > 1:
                sil_score = silhouette_score(X, self.labels)
            else:
                sil_score = 0.0
        except Exception:
            sil_score = 0.0
        
        # Generate cluster summaries
        self._generate_summaries(logs)
        
        metrics = {
            "samples_used": len(logs),
            "clusters_found": self.n_clusters,
            "silhouette_score": round(float(sil_score), 4),
            "algorithm": self.algorithm,
            "model_version": self.model_version,
        }
        
        logger.info(f"Clustering complete: {metrics}")
        return metrics
    
    def predict(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict cluster assignments for logs."""
        if not self.is_fitted:
            logger.warning("Model not fitted yet")
            return []
        
        X = self._extract_features(logs)
        
        if self.algorithm == "kmeans":
            labels = self.model.predict(X)
        else:
            # For DBSCAN, use nearest cluster center
            labels = []
            for x in X:
                distances = []
                for center in self.model.components_:
                    dist = np.linalg.norm(x - center)
                    distances.append(dist)
                labels.append(np.argmin(distances))
        
        results = []
        for label in labels:
            cluster_info = self.cluster_summaries.get(int(label), {})
            results.append({
                "cluster_id": int(label),
                "cluster_label": cluster_info.get("label", f"Cluster {label}"),
                "cluster_description": cluster_info.get("description", ""),
            })
        
        return results
    
    def _generate_summaries(self, logs: List[Dict[str, Any]]):
        """Generate summaries for each cluster."""
        from collections import Counter
        
        self.cluster_summaries = {}
        
        for cluster_id in range(self.n_clusters):
            cluster_logs = [logs[i] for i, label in enumerate(self.labels) if label == cluster_id]
            
            if not cluster_logs:
                continue
            
            # Analyze cluster characteristics
            event_types = Counter(l.get("event_type", "unknown") for l in cluster_logs)
            source_types = Counter(l.get("source_type", "unknown") for l in cluster_logs)
            severities = Counter(l.get("severity", "unknown") for l in cluster_logs)
            ips = Counter(l.get("source_ip", "unknown") for l in cluster_logs if l.get("source_ip"))
            
            # Generate label
            top_event = event_types.most_common(1)[0][0] if event_types else "mixed"
            top_source = source_types.most_common(1)[0][0] if source_types else "mixed"
            
            label = f"{top_source}:{top_event}"
            description = f"Cluster with {len(cluster_logs)} logs. Main event: {top_event}. Source: {top_source}."
            
            self.cluster_summaries[cluster_id] = {
                "label": label,
                "description": description,
                "size": len(cluster_logs),
                "top_event_types": dict(event_types.most_common(5)),
                "top_source_types": dict(source_types.most_common(5)),
                "severity_distribution": dict(severities),
                "top_ips": dict(ips.most_common(5)),
            }
    
    def get_clusters(self) -> List[Dict[str, Any]]:
        """Get cluster information."""
        clusters = []
        for cluster_id, summary in self.cluster_summaries.items():
            clusters.append({
                "cluster_id": cluster_id,
                **summary,
            })
        return sorted(clusters, key=lambda x: x["size"], reverse=True)
    
    def save_model(self, filepath: str) -> str:
        """Save the clustering model."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet")
        
        model_data = {
            "model": self.model,
            "vectorizer": self.vectorizer,
            "model_version": self.model_version,
            "cluster_summaries": self.cluster_summaries,
            "algorithm": self.algorithm,
            "n_clusters": self.n_clusters,
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Clustering model saved to {filepath}")
        return filepath
    
    def load_model(self, filepath: str) -> bool:
        """Load a clustering model."""
        try:
            model_data = joblib.load(filepath)
            
            self.model = model_data["model"]
            self.vectorizer = model_data["vectorizer"]
            self.model_version = model_data.get("model_version", "unknown")
            self.cluster_summaries = model_data.get("cluster_summaries", {})
            self.algorithm = model_data.get("algorithm", "kmeans")
            self.n_clusters = model_data.get("n_clusters", 5)
            self.is_fitted = True
            
            logger.info(f"Clustering model loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load clustering model: {e}")
            return False
