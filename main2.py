import json
import os
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
from pathlib import Path
import javalang
from knowledge_base import VulnerabilityKnowledgeBase
from VulnerabilityFixerModel import VulnerabilityFixerModel

os.environ["CUDA_VISIBLE_DEVICES"] = ""  # Ignore any GPU

# ============================================================================
# SECTION 2: DATA STRUCTURES
# ============================================================================

@dataclass
class Vulnerability:
    """Structure to hold vulnerability information"""
    vuln_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    cwe_id: Optional[str] = None
    recommendation: Optional[str] = None

@dataclass
class CodeContext:
    """Structure to hold code context for fixing"""
    target_file: str
    target_code: str
    imports: List[str]
    class_name: str
    method_name: str
    dependencies: List[str]  # Other files that might need changes
    full_class_code: str

@dataclass
class Fix:
    """Structure to hold generated fix"""
    vuln_id: str
    file_path: str
    original_code: str
    fixed_code: str
    explanation: str
    confidence_score: float
    affected_files: List[str]  # For multi-file changes

# ============================================================================
# SECTION 3: VULNERABILITY PARSER
# ============================================================================

class VulnerabilityParser:
    """Parse vulnerability reports from Trivy/Semgrep"""
    
    @staticmethod
    def parse_trivy_report(report_path: str) -> List[Vulnerability]:
        """Parse Trivy JSON report"""
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = []
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                v = Vulnerability(
                    vuln_id=vuln.get('VulnerabilityID', 'UNKNOWN'),
                    severity=vuln.get('Severity', 'UNKNOWN'),
                    title=vuln.get('Title', ''),
                    description=vuln.get('Description', ''),
                    file_path=result.get('Target', ''),
                    line_number=0,  # Trivy doesn't always provide line numbers
                    code_snippet='',
                    cwe_id=vuln.get('CweIDs', [''])[0] if vuln.get('CweIDs') else None
                )
                vulnerabilities.append(v)
        
        return vulnerabilities
    
    @staticmethod
    def parse_semgrep_report(report_path: str) -> List[Vulnerability]:
        """Parse Semgrep JSON report"""
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = []
        for result in data.get('results', []):
            v = Vulnerability(
                vuln_id=result.get('check_id', 'UNKNOWN'),
                severity=result.get('extra', {}).get('severity', 'MEDIUM').upper(),
                title=result.get('extra', {}).get('message', ''),
                description=result.get('extra', {}).get('metadata', {}).get('description', ''),
                file_path=result.get('path', ''),
                line_number=result.get('start', {}).get('line', 0),
                code_snippet=result.get('extra', {}).get('lines', ''),
                cwe_id=result.get('extra', {}).get('metadata', {}).get('cwe', None),
                recommendation=result.get('extra', {}).get('metadata', {}).get('fix', '')
            )
            vulnerabilities.append(v)
        
        return vulnerabilities

# ============================================================================
# SECTION 4: CODE CONTEXT EXTRACTOR
# ============================================================================

class JavaCodeAnalyzer:
    """Analyze Java code to extract context and dependencies"""
    
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.file_cache = {}
        
    def get_file_content(self, file_path: str) -> str:
        """Read and cache file content"""
        if file_path not in self.file_cache:
            full_path = os.path.join(self.project_root, file_path)
            with open(full_path, 'r', encoding='utf-8') as f:
                self.file_cache[file_path] = f.read()
        return self.file_cache[file_path]
    
    def extract_context(self, vuln: Vulnerability) -> CodeContext:
        """Extract code context around vulnerability"""
        file_content = self.get_file_content(vuln.file_path)
        print(f"  Analyzing file: {vuln.file_path}")
        try:
            tree = javalang.parse.parse(file_content)
            
            # Extract imports
            imports = [imp.path for imp in tree.imports]
            
            # Find the class and method containing the vulnerability
            class_name = ""
            method_name = ""
            target_code = ""
            full_class_code = ""
            
            for path, node in tree.filter(javalang.tree.ClassDeclaration):
                class_name = node.name
                full_class_code = self._extract_node_code(file_content, node)
                
                for method_path, method in node.filter(javalang.tree.MethodDeclaration):
                    method_start = method.position.line if method.position else 0
                    if method_start <= vuln.line_number <= method_start + 50:  # Approximate method end
                        method_name = method.name
                        target_code = self._extract_method_code(file_content, method)
                        break
            
            # Find dependencies (other files that might be affected)
            dependencies = self._find_dependencies(imports)
            print(f"  Found class: {class_name}, method: {method_name}, dependencies: {dependencies}")
            return CodeContext(
                target_file=vuln.file_path,
                target_code=target_code or vuln.code_snippet,
                imports=imports,
                class_name=class_name,
                method_name=method_name,
                dependencies=dependencies,
                full_class_code=full_class_code
            )
            
        except Exception as e:
            print(f"Error parsing Java code: {e}")
            # Fallback: use simple line-based extraction
            return self._extract_context_simple(vuln, file_content)
    
    def _extract_method_code(self, file_content: str, method_node) -> str:
        """Extract method code from AST node"""
        lines = file_content.split('\n')
        start = method_node.position.line - 1 if method_node.position else 0
        # Simple heuristic: extract next 30 lines or until we find a closing brace
        end = min(start + 30, len(lines))
        return '\n'.join(lines[start:end])
    
    def _extract_node_code(self, file_content: str, node) -> str:
        """Extract code for any AST node"""
        # This is simplified; in production, use proper AST traversal
        lines = file_content.split('\n')
        start = node.position.line - 1 if node.position else 0
        return '\n'.join(lines[start:min(start + 100, len(lines))])
    
    def _find_dependencies(self, imports: List[str]) -> List[str]:
        """Find project files that are imported"""
        dependencies = []
        for imp in imports:
            # Check if it's a project import (not java.* or external)
            if not imp.startswith('java.') and not imp.startswith('javax.'):
                # Convert import to file path
                file_path = imp.replace('.', '/') + '.java'
                full_path = os.path.join(self.project_root, file_path)
                if os.path.exists(full_path):
                    dependencies.append(file_path)
        return dependencies
    
    def _extract_context_simple(self, vuln: Vulnerability, file_content: str) -> CodeContext:
        """Fallback method for context extraction"""
        lines = file_content.split('\n')
        start = max(0, vuln.line_number - 10)
        end = min(len(lines), vuln.line_number + 20)
        target_code = '\n'.join(lines[start:end])
        
        # Extract imports from top of file
        imports = [line.strip() for line in lines[:50] 
                   if line.strip().startswith('import')]
        
        return CodeContext(
            target_file=vuln.file_path,
            target_code=target_code,
            imports=imports,
            class_name="Unknown",
            method_name="Unknown",
            dependencies=[],
            full_class_code=file_content
        )

# ============================================================================
# SECTION 7: MAIN ORCHESTRATOR
# ============================================================================

class VulnerabilityFixerOrchestrator:    
    def __init__(self, project_root: str, model_name: str, lora_path: Optional[str] = None):
        self.project_root = project_root
        self.parser = VulnerabilityParser()
        self.code_analyzer = JavaCodeAnalyzer(project_root)
        self.knowledge_base = VulnerabilityKnowledgeBase("fix_patterns.json")
        self.model = VulnerabilityFixerModel(model_name, lora_path)
        
    def process_vulnerability_report(self, report_path: str, report_type: str = "semgrep"):
        """
        Process vulnerability report and generate fixes
        
        Args:
            report_path: Path to vulnerability report JSON
            report_type: Type of report ("semgrep" or "trivy")
        
        Returns:
            List of Fix objects
        """
        print(f"Processing {report_type} report: {report_path}")
        
        # Step 1: Parse vulnerability report
        if report_type == "semgrep":
            vulnerabilities = self.parser.parse_semgrep_report(report_path)
        else:
            vulnerabilities = self.parser.parse_trivy_report(report_path)
        
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        print(vulnerabilities)

        # Step 2: Process each vulnerability
        fixes = []
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n[{i}/{len(vulnerabilities)}] Processing: {vuln.vuln_id}")
            print(f"  Severity: {vuln.severity}")
            print(f"  File: {vuln.file_path}:{vuln.line_number}")
            
            try:
                # Extract code context
                context = self.code_analyzer.extract_context(vuln)
                print(f"  Extracted context: Class {context.class_name}, Method {context.method_name}")
                # Retrieve relevant fix patterns
                fix_patterns = self.knowledge_base.retrieve_relevant_fixes(vuln)
                print(f"  Retrieved {len(fix_patterns)} relevant fix patterns")
                print(fix_patterns)
                # Generate fix
                fix = self.model.generate_fix(vuln, context, fix_patterns)
                fixes.append(fix)
                
                print(f"  ✓ Fix generated (confidence: {fix.confidence_score:.2f})")
                
            except Exception as e:
                print(f"  ✗ Error processing vulnerability: {e}")
                continue
        
        return fixes
    
    def export_fixes(self, fixes: List[Fix], output_path: str):
        """Export fixes to JSON format"""
        output_data = {
            "total_fixes": len(fixes),
            "fixes": [
                {
                    "vuln_id": fix.vuln_id,
                    "file_path": fix.file_path,
                    "original_code": fix.original_code,
                    "fixed_code": fix.fixed_code,
                    "explanation": fix.explanation,
                    "confidence_score": fix.confidence_score,
                    "affected_files": fix.affected_files
                }
                for fix in fixes
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\nFixes exported to: {output_path}")
    
    def generate_patch_files(self, fixes: List[Fix], output_dir: str):
        """Generate unified diff patch files"""
        os.makedirs(output_dir, exist_ok=True)
        
        for i, fix in enumerate(fixes, 1):
            patch_file = os.path.join(output_dir, f"fix_{i}_{fix.vuln_id}.patch")
            
            with open(patch_file, 'w') as f:
                f.write(f"# Vulnerability: {fix.vuln_id}\n")
                f.write(f"# File: {fix.file_path}\n")
                f.write(f"# Confidence: {fix.confidence_score:.2f}\n")
                f.write(f"# Explanation: {fix.explanation}\n\n")
                f.write(f"--- a/{fix.file_path}\n")
                f.write(f"+++ b/{fix.file_path}\n")
                f.write("\n--- ORIGINAL CODE ---\n")
                f.write(fix.original_code)
                f.write("\n\n+++ FIXED CODE +++\n")
                f.write(fix.fixed_code)
                f.write("\n")
        
        print(f"Patch files generated in: {output_dir}")


def main():    
    # Configuration
    PROJECT_ROOT = "./"  # Your Java project path
    REPORT_PATH = "./semgrep_report.json"  # Vulnerability report
    OUTPUT_JSON = "./fixes.json"
    OUTPUT_PATCHES = "./patches"
    
    # Initialize orchestrator
    print("="*80)
    print("AI-Powered Vulnerability Fixer")
    print("="*80)
    
    orchestrator = VulnerabilityFixerOrchestrator(
        project_root=PROJECT_ROOT,
        model_name="gpt2",
        lora_path="../models/fine_tunning"  # Path to LoRA adapters if any 
    )
    
    print("orchestrator initialized")

    # Process vulnerabilities
    fixes = orchestrator.process_vulnerability_report(
        report_path=REPORT_PATH,
        report_type="semgrep"  # or "trivy"
    )
    
    print(f"\nTotal fixes generated: {len(fixes)}")
    # Export results
    orchestrator.export_fixes(fixes, OUTPUT_JSON)
    orchestrator.generate_patch_files(fixes, OUTPUT_PATCHES)
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total vulnerabilities processed: {len(fixes)}")
    print(f"High confidence fixes (>0.7): {sum(1 for f in fixes if f.confidence_score > 0.7)}")
    print(f"Medium confidence fixes (0.5-0.7): {sum(1 for f in fixes if 0.5 <= f.confidence_score <= 0.7)}")
    print(f"Low confidence fixes (<0.5): {sum(1 for f in fixes if f.confidence_score < 0.5)}")
    print("\nOutput files:")
    print(f"  - JSON: {OUTPUT_JSON}")


main()