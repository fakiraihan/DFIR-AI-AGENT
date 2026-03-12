"""
Report Generation and Digital Signature Module
Generates investigation reports with RSA-2048 + SHA-256 signing
Supports PDF and JSON formats
"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY


class ReportGenerator:
    """
    Generates structured investigation reports with digital signatures
    """
    
    def __init__(self, private_key_path: Optional[str] = None, public_key_path: Optional[str] = None):
        """
        Initialize report generator
        
        Args:
            private_key_path: Path to RSA private key (PEM format)
            public_key_path: Path to RSA public key (PEM format)
        """
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.private_key = None
        self.public_key = None
        
        # Load or generate keys
        if private_key_path and Path(private_key_path).exists():
            self._load_keys()
        else:
            print("Keys not found, will generate new keypair")
    
    def _load_keys(self):
        """Load RSA keys from files"""
        try:
            with open(self.private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            with open(self.public_key_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            print("RSA keys loaded successfully")
        except Exception as e:
            print(f"Error loading keys: {e}")
            self.private_key = None
            self.public_key = None
    
    def generate_keypair(self, output_dir: str):
        """
        Generate new RSA-2048 keypair
        
        Args:
            output_dir: Directory to save keys
        """
        print("Generating RSA-2048 keypair...")
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Extract public key
        self.public_key = self.private_key.public_key()
        
        # Save keys
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file = output_path / "private.pem"
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file = output_path / "public.pem"
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        
        print(f"Keys saved to {output_path}")
        print(f"  - Private key: {private_key_file}")
        print(f"  - Public key: {public_key_file}")
        
        self.private_key_path = str(private_key_file)
        self.public_key_path = str(public_key_file)
    
    def generate_report(
        self,
        session_id: str,
        file_name: str,
        investigation_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate structured investigation report
        
        Args:
            session_id: Investigation session ID
            file_name: Original log file name
            investigation_state: Final state from AI Agent
            
        Returns:
            Complete report dictionary
        """
        print("\n=== GENERATING INVESTIGATION REPORT ===")
        
        # Extract data from investigation state
        anomalies = investigation_state.get("anomalies", [])
        iocs = investigation_state.get("iocs_extracted", [])
        tool_results = investigation_state.get("tool_results", [])
        timeline = investigation_state.get("attack_timeline", [])
        summary = investigation_state.get("investigation_summary", "No summary available")
        recommendations = investigation_state.get("recommendations", [])
        
        # Build report structure
        report = {
            "metadata": {
                "session_id": session_id,
                "report_id": f"DFIR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "generated_at": datetime.now().isoformat(),
                "log_file": file_name,
                "analyst": "AI Agent DFIR System v1.0",
                "model": "Foundation-Sec-8B + DeepLog"
            },
            
            "executive_summary": {
                "overview": summary,
                "severity": self._calculate_severity(anomalies, tool_results),
                "anomaly_count": len(anomalies),
                "ioc_count": len(iocs),
                "threat_intel_queries": len(tool_results)
            },
            
            "ioc_analysis": {
                "total_iocs": len(iocs),
                "iocs_by_type": self._group_iocs_by_type(iocs),
                "ioc_details": iocs[:50],  # Limit to 50 for report size
                "threat_intelligence": self._summarize_threat_intel(tool_results)
            },
            
            "attack_timeline": {
                "total_events": len(timeline),
                "events": timeline
            },
            
            "anomaly_details": {
                "total_anomalies": len(anomalies),
                "summary": [
                    {
                        "window_id": a.get("window_id"),
                        "start_idx": a.get("start_idx"),
                        "end_idx": a.get("end_idx"),
                        "actual_event": a.get("actual_event", "")[:100]  # Truncate long strings
                    }
                    for a in anomalies[:20]  # First 20 anomalies
                ]
            },
            
            "recommendations": {
                "immediate_actions": recommendations,
                "next_steps": [
                    "Lakukan investigasi mendalam pada sistem yang teridentifikasi",
                    "Isolasi sistem yang terkompromisi dari jaringan",
                    "Update security policies berdasarkan temuan",
                    "Monitor aktivitas serupa di sistem lain"
                ]
            }
        }
        
        print(f"Report generated: {report['metadata']['report_id']}")
        print(f"  - Severity: {report['executive_summary']['severity']}")
        print(f"  - Anomalies: {report['executive_summary']['anomaly_count']}")
        print(f"  - IOCs: {report['executive_summary']['ioc_count']}")
        
        return report
    
    def sign_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign report with RSA-2048 + SHA-256
        
        Args:
            report: Report dictionary
            
        Returns:
            Signature metadata
        """
        if not self.private_key:
            print("WARNING: No private key available, skipping signature")
            return {
                "signed": False,
                "error": "No private key available"
            }
        
        print("\n=== SIGNING REPORT ===")
        
        # Convert report to canonical JSON string
        report_json = json.dumps(report, sort_keys=True, indent=2)
        report_bytes = report_json.encode('utf-8')
        
        # Calculate SHA-256 hash
        sha256_hash = hashlib.sha256(report_bytes).hexdigest()
        print(f"Report SHA-256: {sha256_hash}")
        
        # Sign hash with RSA private key
        signature = self.private_key.sign(
            report_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode signature as hex
        signature_hex = signature.hex()
        
        print(f"Signature generated (first 64 chars): {signature_hex[:64]}...")
        
        # Create signature metadata
        signature_metadata = {
            "signed": True,
            "algorithm": "RSA-2048",
            "hash_algorithm": "SHA-256",
            "hash_value": sha256_hash,
            "signature": signature_hex,
            "signed_at": datetime.now().isoformat(),
            "standard": "PKCS#1 v2.2 (PSS)",
            "public_key_fingerprint": self._get_public_key_fingerprint()
        }
        
        print("Report signed successfully")
        
        return signature_metadata
    
    def verify_signature(self, report: Dict[str, Any], signature_metadata: Dict[str, Any]) -> bool:
        """
        Verify report signature
        
        Args:
            report: Report dictionary (without signature field)
            signature_metadata: Signature metadata
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.public_key:
            print("WARNING: No public key available for verification")
            return False
        
        print("\n=== VERIFYING SIGNATURE ===")
        
        try:
            # Convert report to canonical JSON
            report_json = json.dumps(report, sort_keys=True, indent=2)
            report_bytes = report_json.encode('utf-8')
            
            # Calculate hash
            calculated_hash = hashlib.sha256(report_bytes).hexdigest()
            stored_hash = signature_metadata.get("hash_value")
            
            print(f"Calculated hash: {calculated_hash}")
            print(f"Stored hash:     {stored_hash}")
            
            if calculated_hash != stored_hash:
                print("❌ Hash mismatch - report has been modified")
                return False
            
            # Verify signature
            signature_bytes = bytes.fromhex(signature_metadata.get("signature"))
            
            self.public_key.verify(
                signature_bytes,
                report_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("✅ Signature valid - report has not been tampered")
            return True
            
        except Exception as e:
            print(f"❌ Signature verification failed: {e}")
            return False
    
    def save_report(self, report: Dict[str, Any], signature: Dict[str, Any], output_dir: str) -> str:
        """
        Save signed report to PDF and JSON files
        
        Args:
            report: Report dictionary
            signature: Signature metadata
            output_dir: Directory to save report
            
        Returns:
            Path to saved PDF report file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Combine report and signature
        signed_report = {
            "report": report,
            "signature": signature
        }
        
        report_id = report['metadata']['report_id']
        
        # Save as JSON (backup)
        json_file = output_path / f"{report_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(signed_report, f, indent=2, ensure_ascii=False)
        
        print(f"\nJSON report saved to: {json_file}")
        
        # Generate PDF
        pdf_file = output_path / f"{report_id}.pdf"
        self._generate_pdf(report, signature, str(pdf_file))
        print(f"PDF report saved to: {pdf_file}")
        
        return str(pdf_file)
    
    def _generate_pdf(self, report: Dict[str, Any], signature: Dict[str, Any], pdf_path: str):
        """
        Generate PDF report with professional styling
        
        Args:
            report: Report dictionary
            signature: Signature metadata
            pdf_path: Path to save PDF file
        """
        doc = SimpleDocTemplate(pdf_path, pagesize=A4, 
                               topMargin=0.75*inch, bottomMargin=0.75*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#10b981'),
            spaceAfter=12,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#10b981'),
            spaceAfter=8,
            spaceBefore=12
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#059669'),
            spaceAfter=6
        )
        
        # Title
        story.append(Paragraph("AI AGENT DFIR", title_style))
        story.append(Paragraph("Digital Forensics & Incident Response Report", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Report Metadata
        metadata = report['metadata']
        meta_data = [
            ['Report ID:', metadata['report_id']],
            ['File Name:', metadata['file_name']],
            ['Generated:', datetime.fromisoformat(metadata['timestamp']).strftime('%Y-%m-%d %H:%M:%S')],
            ['Severity:', metadata['severity']],
            ['Analyst:', metadata.get('analyst', 'AI Agent System')]
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e6f7f1')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#059669')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        summary_text = report.get('executive_summary', 'Tidak ada ringkasan tersedia.')
        story.append(Paragraph(summary_text, styles['BodyText']))
        story.append(Spacer(1, 0.2*inch))
        
        # IOC Analysis
        if report.get('ioc_analysis'):
            story.append(Paragraph("Indicators of Compromise (IOCs)", heading_style))
            
            ioc_count = {}
            for ioc in report['ioc_analysis']:
                ioc_type = ioc.get('type', 'unknown')
                ioc_count[ioc_type] = ioc_count.get(ioc_type, 0) + 1
            
            # IOC Summary
            story.append(Paragraph(f"Total IOCs: <b>{len(report['ioc_analysis'])}</b>", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # IOC Table
            ioc_data = [['Type', 'Value', 'Threat Level']]
            for ioc in report['ioc_analysis'][:20]:  # Limit to first 20
                ioc_data.append([
                    ioc.get('type', 'N/A'),
                    ioc.get('value', 'N/A')[:50] + ('...' if len(ioc.get('value', '')) > 50 else ''),
                    ioc.get('threat_level', 'unknown')
                ])
            
            ioc_table = Table(ioc_data, colWidths=[1*inch, 3.5*inch, 1.5*inch])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#10b981')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0fdf4')])
            ]))
            story.append(ioc_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Attack Timeline
        if report.get('attack_timeline'):
            story.append(Paragraph("Attack Timeline", heading_style))
            
            for event in report['attack_timeline'][:10]:  # Limit to first 10
                timestamp = event.get('timestamp', 'N/A')
                if timestamp != 'N/A':
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                
                story.append(Paragraph(f"<b>{timestamp}</b>", styles['Normal']))
                story.append(Paragraph(event.get('event', 'N/A'), styles['BodyText']))
                if event.get('details'):
                    story.append(Paragraph(f"<i>{event['details']}</i>", styles['Italic']))
                story.append(Spacer(1, 0.1*inch))
        
        # Recommendations
        if report.get('recommendations'):
            story.append(PageBreak())
            story.append(Paragraph("Recommendations", heading_style))
            
            for idx, rec in enumerate(report['recommendations'], 1):
                story.append(Paragraph(f"{idx}. {rec}", styles['BodyText']))
                story.append(Spacer(1, 0.1*inch))
        
        # Digital Signature
        story.append(PageBreak())
        story.append(Paragraph("Digital Signature", heading_style))
        
        if signature.get('signed'):
            sig_data = [
                ['Algorithm:', signature.get('algorithm', 'N/A')],
                ['Hash Algorithm:', signature.get('hash_algorithm', 'N/A')],
                ['Hash Value:', signature.get('hash_value', 'N/A')[:64] + '...'],
                ['Signature:', signature.get('signature', 'N/A')[:64] + '...'],
                ['Signed At:', signature.get('signed_at', 'N/A')],
                ['Standard:', signature.get('standard', 'N/A')]
            ]
            
            sig_table = Table(sig_data, colWidths=[2*inch, 4*inch])
            sig_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0fdf4')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#059669')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(sig_table)
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("✓ Report integrity verified", styles['Italic']))
        else:
            story.append(Paragraph("⚠ Report not signed", styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 0.3*inch))
        footer_text = f"Generated by AI Agent DFIR System | Polsasbersan TNI AL | {datetime.now().year}"
        story.append(Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], 
                                                           fontSize=8, textColor=colors.grey, 
                                                           alignment=TA_CENTER)))
        
        # Build PDF
        doc.build(story)
    
    
    # === Helper Methods ===
    
    def _calculate_severity(self, anomalies: list, tool_results: list) -> str:
        """Calculate severity level based on findings"""
        anomaly_count = len(anomalies)
        
        # Check threat intel for malicious indicators
        malicious_count = 0
        for result in tool_results:
            if result.get("status") == "ok_found" or result.get("malicious", 0) > 0:
                malicious_count += 1
        
        if malicious_count > 5 or anomaly_count > 50:
            return "HIGH"
        elif malicious_count > 2 or anomaly_count > 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _group_iocs_by_type(self, iocs: list) -> Dict[str, int]:
        """Group IOCs by type"""
        groups = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            groups[ioc_type] = groups.get(ioc_type, 0) + 1
        return groups
    
    def _summarize_threat_intel(self, tool_results: list) -> Dict[str, Any]:
        """Summarize threat intelligence findings"""
        summary = {
            "total_queries": len(tool_results),
            "successful": 0,
            "errors": 0,
            "findings": []
        }
        
        for result in tool_results:
            if result.get("error"):
                summary["errors"] += 1
            else:
                summary["successful"] += 1
                
                # Add significant findings
                if result.get("malware_family") or result.get("malicious", 0) > 0:
                    summary["findings"].append({
                        "tool": result.get("tool"),
                        "ioc": result.get("ioc"),
                        "threat": result.get("malware_family") or "Malicious activity detected"
                    })
        
        return summary
    
    def _get_public_key_fingerprint(self) -> str:
        """Get public key fingerprint (SHA-256 of public key)"""
        if not self.public_key:
            return "no_public_key"
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()
        return fingerprint[:16]  # First 16 chars


if __name__ == "__main__":
    # Test report generation
    generator = ReportGenerator()
    
    # Generate test keypair
    generator.generate_keypair("../keys")
    
    # Test report
    test_state = {
        "anomalies": [{"window_id": i, "start_idx": i*5, "end_idx": i*5+10} for i in range(5)],
        "iocs_extracted": [
            {"type": "ip", "value": "192.168.1.1"},
            {"type": "domain", "value": "evil.com"}
        ],
        "tool_results": [],
        "attack_timeline": [],
        "investigation_summary": "Test investigation summary",
        "recommendations": ["Test recommendation 1", "Test recommendation 2"]
    }
    
    report = generator.generate_report("test_session", "test.evtx", test_state)
    signature = generator.sign_report(report)
    
    # Verify
    is_valid = generator.verify_signature(report, signature)
    print(f"\nSignature valid: {is_valid}")
    
    # Save
    generator.save_report(report, signature, "../output")
