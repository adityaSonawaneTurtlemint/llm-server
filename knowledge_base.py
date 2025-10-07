from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
from pathlib import Path
import json

# ============================================================================
# RAG SYSTEM FOR VULNERABILITY FIXES
# ============================================================================

class VulnerabilityKnowledgeBase:
    """RAG system to retrieve relevant fix patterns"""
    
    def __init__(self, patterns_file: str):
        print("[VulnerabilityKnowledgeBase] patterns_file:", patterns_file)
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.index = None
        self.fix_patterns = self._load_patterns(patterns_file)
        self._build_index()

    def _load_patterns(self, file_path: str):
        """Load fix patterns from JSON file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Fix patterns file not found: {file_path}")
        with open(path, 'r') as f:
            return json.load(f)
           
    def _build_index(self):
        """Build FAISS index for similarity search"""
        texts = []
        for pattern in self.fix_patterns:
            text = f"{pattern['vuln_type']} {pattern['cwe']} {pattern['pattern']} {pattern['fix_description']}"
            texts.append(text)
        
        print(f"[VulnerabilityKnowledgeBase] Encoding {len(texts)} fix patterns...")
        embeddings = self.embedder.encode(texts)
        dimension = embeddings.shape[1]
        
        self.index = faiss.IndexFlatL2(dimension)
        self.index.add(embeddings.astype('float32'))
        print(f"[VulnerabilityKnowledgeBase] Built FAISS index with {self.index.ntotal} vectors.")
    
    def retrieve_relevant_fixes(self, vuln, top_k: int = 3):
        """Retrieve most relevant fix patterns for a vulnerability"""
        query_text = f"{vuln.title} {vuln.description} {vuln.cwe_id or ''}"
        query_embedding = self.embedder.encode([query_text])
        
        distances, indices = self.index.search(query_embedding.astype('float32'), top_k)
        
        relevant_fixes = []
        for idx in indices[0]:
            if idx < len(self.fix_patterns):
                relevant_fixes.append(self.fix_patterns[idx])
        
        return relevant_fixes
