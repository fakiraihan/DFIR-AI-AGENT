"""
Procedural Memory for DFIR AI Agent
Stores learned procedures, API documentation, and investigation strategies
Persists to disk for cross-session learning
"""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
DEFAULT_MEMORY_RESOURCE = (
    Path(__file__).resolve().parent.parent
    / "resources"
    / "procedural_memory_defaults.json"
)


class ProceduralMemory:
    """
    Long-term procedural knowledge for DFIR investigation
    Learns from experience and maintains API best practices
    """
    
    def __init__(self, storage_path: str = "data/procedural_memory.json"):
        self.storage_path = Path(storage_path)
        self.memory = self._load_memory()
        logger.info(f"Procedural Memory initialized from {storage_path}")
    
    def _load_memory(self) -> Dict:
        """Load existing procedural memory from disk"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    memory = json.load(f)
                    logger.info(f"Loaded existing procedural memory with {len(memory.get('api_documentation', {}))} API configs")
                    return memory
            except Exception as e:
                logger.error(f"Error loading procedural memory: {e}, initializing default")
                return self._initialize_default_memory()
        else:
            logger.info("No existing procedural memory found, initializing default")
            return self._initialize_default_memory()
    
    def _initialize_default_memory(self) -> Dict:
        """Load baseline procedural knowledge from the bundled JSON resource."""
        try:
            with open(DEFAULT_MEMORY_RESOURCE, "r", encoding="utf-8") as f:
                memory = json.load(f)
        except Exception as e:
            logger.error(
                "Error loading default procedural memory from "
                f"{DEFAULT_MEMORY_RESOURCE}: {e}"
            )
            raise

        now = datetime.now().isoformat()
        metadata = memory.setdefault("metadata", {})
        metadata["created"] = metadata.get("created") or now
        metadata["last_updated"] = metadata.get("last_updated") or now
        metadata.setdefault("total_investigations", 0)
        return memory
    
    def get_api_strategy(self, ioc_type: str) -> Dict[str, Any]:
        """
        Retrieve learned strategy for specific IOC type
        
        Args:
            ioc_type: Type of IOC (ip_address, file_hash, domain, url)
        
        Returns:
            Strategy dict with primary tool, fallbacks, and execution rules
        """
        strategy = self.memory["tool_selection_rules"].get(ioc_type, {})
        
        if not strategy:
            logger.warning(f"No strategy found for IOC type: {ioc_type}, using default")
            return {
                "primary": None,
                "fallback": [],
                "parallel_allowed": False,
                "reason": "No learned strategy available"
            }
        
        logger.debug(f"Retrieved strategy for {ioc_type}: primary={strategy.get('primary')}")
        return strategy
    
    def get_api_documentation(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive API documentation for a specific tool
        
        Args:
            tool_name: Name of the threat intel tool
        
        Returns:
            Complete API documentation dict or None
        """
        doc = self.memory["api_documentation"].get(tool_name)
        
        if not doc:
            logger.warning(f"No documentation found for tool: {tool_name}")
            return None
        
        logger.debug(f"Retrieved documentation for {tool_name}: endpoint={doc.get('endpoint')}")
        return doc
    
    def get_playbook(self, scenario: str) -> Optional[Dict[str, Any]]:
        """
        Get investigation playbook for specific scenario
        
        Args:
            scenario: Investigation scenario identifier
        
        Returns:
            Playbook dict with steps and metadata or None
        """
        playbook = self.memory["investigation_playbooks"].get(scenario)
        
        if not playbook:
            logger.warning(f"No playbook found for scenario: {scenario}")
            return None
        
        logger.info(f"Retrieved playbook for {scenario}: {len(playbook.get('steps', []))} steps")
        return playbook
    
    def update_tool_performance(
        self, 
        tool: str, 
        success: bool, 
        response_time: float,
        ioc_type: Optional[str] = None
    ):
        """
        Learn from tool execution results
        Updates reliability score and response time using moving average
        
        Args:
            tool: Tool name
            success: Whether the tool call succeeded
            response_time: Response time in seconds
            ioc_type: Type of IOC being queried (optional)
        """
        # Update API documentation learned patterns
        if tool in self.memory["api_documentation"]:
            api_doc = self.memory["api_documentation"][tool]
            learned = api_doc.get("learned_patterns", {})
            
            # Update success rate (exponential moving average, alpha=0.05)
            current_rate = learned.get("success_rate", 0.5)
            new_rate = current_rate * 0.95 + (1.0 if success else 0.0) * 0.05
            learned["success_rate"] = round(new_rate, 3)
            
            # Update response time (exponential moving average, alpha=0.1)
            current_time = learned.get("typical_response_time", 1.0)
            new_time = current_time * 0.9 + response_time * 0.1
            learned["typical_response_time"] = round(new_time, 2)
            
            api_doc["learned_patterns"] = learned
        
        # Update performance metrics
        metrics = self.memory["performance_metrics"]
        
        # Track total calls
        total_key = f"{tool}_total"
        metrics["tool_reliability"][total_key] = metrics["tool_reliability"].get(total_key, 0) + 1
        
        # Track successful calls
        if success:
            success_key = f"{tool}_success"
            metrics["tool_reliability"][success_key] = metrics["tool_reliability"].get(success_key, 0) + 1
        
        # Track response times
        if tool not in metrics["tool_response_times"]:
            metrics["tool_response_times"][tool] = []
        metrics["tool_response_times"][tool].append(response_time)
        
        # Keep only last 100 response times
        if len(metrics["tool_response_times"][tool]) > 100:
            metrics["tool_response_times"][tool] = metrics["tool_response_times"][tool][-100:]
        
        # Calculate success rate
        total = metrics["tool_reliability"].get(f"{tool}_total", 1)
        success_count = metrics["tool_reliability"].get(f"{tool}_success", 0)
        metrics["tool_success_rates"][tool] = round(success_count / total, 3)
        
        logger.info(
            f"Updated performance for {tool}: "
            f"success_rate={metrics['tool_success_rates'].get(tool, 0):.2%}, "
            f"response_time={response_time:.2f}s"
        )
        
        self._save_memory()
    
    def record_successful_investigation(
        self, 
        tool_sequence: List[str], 
        attack_type: str,
        investigation_time: float
    ):
        """
        Learn which tool sequences work best for specific attack types
        
        Args:
            tool_sequence: List of tools used in order
            attack_type: Type of attack investigated
            investigation_time: Total investigation time in seconds
        """
        patterns = self.memory["learned_patterns"]
        
        # Update investigation count
        patterns["successful_investigations"] += 1
        
        # Update average investigation time
        current_avg = patterns.get("average_investigation_time", 0)
        total_inv = patterns["successful_investigations"]
        new_avg = ((current_avg * (total_inv - 1)) + investigation_time) / total_inv
        patterns["average_investigation_time"] = round(new_avg, 2)
        
        # Record optimal tool sequence for this attack type
        key = f"{attack_type}_sequence"
        if key not in patterns["optimal_tool_sequences"]:
            patterns["optimal_tool_sequences"][key] = {}
        
        sequence_key = "_".join(tool_sequence)
        current_count = patterns["optimal_tool_sequences"][key].get(sequence_key, 0)
        patterns["optimal_tool_sequences"][key][sequence_key] = current_count + 1
        
        logger.info(
            f"Recorded successful investigation #{patterns['successful_investigations']}: "
            f"{attack_type} using {len(tool_sequence)} tools in {investigation_time:.1f}s"
        )
        
        self._save_memory()
    
    def get_optimal_tool_sequence(self, attack_type: str) -> Optional[List[str]]:
        """
        Get the most successful tool sequence for a given attack type
        
        Args:
            attack_type: Type of attack
        
        Returns:
            List of tool names in optimal order, or None
        """
        key = f"{attack_type}_sequence"
        sequences = self.memory["learned_patterns"]["optimal_tool_sequences"].get(key, {})
        
        if not sequences:
            logger.debug(f"No learned sequences for attack type: {attack_type}")
            return None
        
        # Return the most frequently successful sequence
        best_sequence = max(sequences.items(), key=lambda x: x[1])
        tools = best_sequence[0].split("_")
        
        logger.info(f"Optimal sequence for {attack_type}: {tools} (used {best_sequence[1]} times)")
        return tools
    
    def add_false_positive_pattern(self, pattern: str, description: str):
        """
        Record a false positive pattern to avoid in future
        
        Args:
            pattern: Pattern that caused false positive
            description: Description of why it's false positive
        """
        fp_entry = {
            "pattern": pattern,
            "description": description,
            "timestamp": datetime.now().isoformat()
        }
        
        self.memory["learned_patterns"]["common_false_positives"].append(fp_entry)
        
        logger.info(f"Recorded false positive pattern: {pattern}")
        self._save_memory()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about procedural memory
        
        Returns:
            Statistics dictionary
        """
        patterns = self.memory["learned_patterns"]
        metrics = self.memory["performance_metrics"]
        
        stats = {
            "total_investigations": patterns["successful_investigations"],
            "average_investigation_time": patterns.get("average_investigation_time", 0),
            "total_apis": len(self.memory["api_documentation"]),
            "total_playbooks": len(self.memory["investigation_playbooks"]),
            "tool_performance": {},
            "last_updated": self.memory["metadata"]["last_updated"]
        }
        
        # Add tool performance stats
        for tool in self.memory["api_documentation"].keys():
            success_rate = metrics["tool_success_rates"].get(tool, 0)
            response_times = metrics["tool_response_times"].get(tool, [])
            avg_time = sum(response_times) / len(response_times) if response_times else 0
            
            stats["tool_performance"][tool] = {
                "success_rate": success_rate,
                "avg_response_time": round(avg_time, 2),
                "total_calls": metrics["tool_reliability"].get(f"{tool}_total", 0)
            }
        
        return stats
    
    def _save_memory(self):
        """Persist memory to disk"""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            self.memory["metadata"]["last_updated"] = datetime.now().isoformat()
            self.memory["metadata"]["total_investigations"] = self.memory["learned_patterns"]["successful_investigations"]
            
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(self.memory, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Procedural memory saved to {self.storage_path}")
        except Exception as e:
            logger.error(f"Error saving procedural memory: {e}")
    
    def export_api_summary(self, output_path: Optional[str] = None) -> str:
        """
        Export API documentation summary for reference
        
        Args:
            output_path: Optional path to save summary
        
        Returns:
            Formatted summary string
        """
        summary_lines = ["# DFIR AI Agent - Threat Intelligence API Summary\n"]
        summary_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for tool_name, doc in self.memory["api_documentation"].items():
            summary_lines.append(f"## {doc['service_name']} ({tool_name})\n")
            summary_lines.append(f"- **Provider**: {doc['provider']}\n")
            summary_lines.append(f"- **Endpoint**: {doc['endpoint']}\n")
            summary_lines.append(f"- **Auth**: {doc['auth_method']} via `{doc.get('auth_header', doc.get('auth_parameter', 'N/A'))}`\n")
            summary_lines.append(f"- **Rate Limit**: {doc['rate_limit']}\n")
            summary_lines.append(f"- **Cost**: {doc['cost']}\n")
            summary_lines.append(f"- **Best For**: {', '.join(doc['best_for'])}\n")
            summary_lines.append(f"- **Reliability Score**: {doc['reliability_score']:.2%}\n")
            summary_lines.append(f"- **Avg Response Time**: {doc['avg_response_time']}s\n")
            
            learned = doc.get("learned_patterns", {})
            if learned:
                summary_lines.append(f"- **Learned Success Rate**: {learned.get('success_rate', 0):.2%}\n")
                summary_lines.append(f"- **Typical Response Time**: {learned.get('typical_response_time', 0)}s\n")
            
            summary_lines.append("\n")
        
        summary = "".join(summary_lines)
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(summary)
                logger.info(f"API summary exported to {output_path}")
            except Exception as e:
                logger.error(f"Error exporting API summary: {e}")
        
        return summary


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize procedural memory
    pm = ProceduralMemory("../../data/procedural_memory.json")
    
    # Get strategy for IP address
    strategy = pm.get_api_strategy("ip_address")
    print(f"IP Strategy: {strategy}")
    
    # Get API documentation
    greynoise_doc = pm.get_api_documentation("greynoise")
    print(f"\nGreyNoise Endpoint: {greynoise_doc['endpoint']}")
    
    # Simulate learning from tool execution
    pm.update_tool_performance("greynoise", success=True, response_time=0.85)
    pm.update_tool_performance("threatfox", success=True, response_time=1.2)
    
    # Record successful investigation
    pm.record_successful_investigation(
        tool_sequence=["greynoise", "threatfox", "alienvault_otx"],
        attack_type="suspicious_network_activity",
        investigation_time=420.5  # 7 minutes
    )
    
    # Get statistics
    stats = pm.get_statistics()
    print(f"\nProcedural Memory Statistics:")
    print(f"Total investigations: {stats['total_investigations']}")
    print(f"Average time: {stats['average_investigation_time']:.1f}s")
    
    # Export API summary
    summary = pm.export_api_summary()
    print(f"\n{summary[:500]}...")
