"""
Test script for Procedural Memory module
Demonstrates functionality and validates implementation
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.procedural_memory import ProceduralMemory
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_initialization():
    """Test procedural memory initialization"""
    print("\n" + "="*60)
    print("TEST 1: Initialization")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    print(f"✓ Procedural memory initialized successfully")
    print(f"✓ Loaded {len(pm.memory['api_documentation'])} API configurations")
    print(f"✓ Loaded {len(pm.memory['investigation_playbooks'])} investigation playbooks")
    
    return pm


def test_api_strategies():
    """Test API strategy retrieval"""
    print("\n" + "="*60)
    print("TEST 2: API Strategy Retrieval")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    # Test different IOC types
    ioc_types = ["ip_address", "file_hash", "domain", "url"]
    
    for ioc_type in ioc_types:
        strategy = pm.get_api_strategy(ioc_type)
        print(f"\n{ioc_type.upper()} Strategy:")
        print(f"  Primary: {strategy.get('primary')}")
        print(f"  Fallback: {strategy.get('fallback')}")
        print(f"  Reason: {strategy.get('reason')}")
        print(f"  Parallel: {strategy.get('parallel_allowed')}")


def test_api_documentation():
    """Test API documentation retrieval"""
    print("\n" + "="*60)
    print("TEST 3: API Documentation")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    tools = ["greynoise", "threatfox", "malwarebazaar", "urlhaus", "alienvault_otx"]
    
    for tool in tools:
        doc = pm.get_api_documentation(tool)
        if doc:
            print(f"\n{doc['service_name']}:")
            print(f"  Endpoint: {doc['endpoint']}")
            print(f"  Auth: {doc['auth_method']} via {doc.get('auth_header', doc.get('auth_parameter'))}")
            print(f"  Rate Limit: {doc['rate_limit']}")
            print(f"  Best For: {', '.join(doc['best_for'][:3])}")
            print(f"  Cost: {doc['cost']}")
            print(f"  Reliability: {doc['reliability_score']:.1%}")


def test_playbooks():
    """Test investigation playbook retrieval"""
    print("\n" + "="*60)
    print("TEST 4: Investigation Playbooks")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    scenarios = list(pm.memory['investigation_playbooks'].keys())
    
    for scenario in scenarios:
        playbook = pm.get_playbook(scenario)
        if playbook:
            print(f"\n{scenario.replace('_', ' ').title()}:")
            print(f"  Description: {playbook['description']}")
            print(f"  Priority: {playbook['priority']}")
            print(f"  Estimated Time: {playbook['estimated_time']}")
            print(f"  Steps ({len(playbook['steps'])}):")
            for i, step in enumerate(playbook['steps'][:3], 1):
                print(f"    {i}. {step.replace('_', ' ').title()}")
            if len(playbook['steps']) > 3:
                print(f"    ... and {len(playbook['steps']) - 3} more steps")


def test_performance_learning():
    """Test performance learning from tool execution"""
    print("\n" + "="*60)
    print("TEST 5: Performance Learning")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    # Simulate multiple tool executions
    print("\nSimulating tool executions...")
    
    # GreyNoise - fast and reliable
    for i in range(10):
        pm.update_tool_performance("greynoise", success=True, response_time=0.8 + (i * 0.1))
    
    # ThreatFox - moderate speed
    for i in range(8):
        pm.update_tool_performance("threatfox", success=True, response_time=1.5 + (i * 0.2))
    pm.update_tool_performance("threatfox", success=False, response_time=5.0)
    pm.update_tool_performance("threatfox", success=False, response_time=4.5)
    
    # MalwareBazaar - reliable but slower
    for i in range(7):
        pm.update_tool_performance("malwarebazaar", success=True, response_time=2.0 + (i * 0.15))
    
    print("\nPerformance after learning:")
    stats = pm.get_statistics()
    
    for tool, perf in stats['tool_performance'].items():
        if perf['total_calls'] > 0:
            print(f"\n{tool.upper()}:")
            print(f"  Success Rate: {perf['success_rate']:.1%}")
            print(f"  Avg Response Time: {perf['avg_response_time']:.2f}s")
            print(f"  Total Calls: {perf['total_calls']}")


def test_investigation_recording():
    """Test recording successful investigations"""
    print("\n" + "="*60)
    print("TEST 6: Investigation Recording")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    # Record several investigations
    investigations = [
        {
            "tools": ["greynoise", "threatfox"],
            "attack": "suspicious_network_activity",
            "time": 420.5
        },
        {
            "tools": ["greynoise", "threatfox", "alienvault_otx"],
            "attack": "suspicious_network_activity",
            "time": 480.2
        },
        {
            "tools": ["malwarebazaar", "virustotal"],
            "attack": "malware_hash_detected",
            "time": 350.7
        },
        {
            "tools": ["greynoise", "threatfox"],
            "attack": "suspicious_network_activity",
            "time": 390.1
        }
    ]
    
    print("\nRecording investigations...")
    for inv in investigations:
        pm.record_successful_investigation(
            tool_sequence=inv["tools"],
            attack_type=inv["attack"],
            investigation_time=inv["time"]
        )
    
    # Get optimal sequences
    print("\nOptimal Tool Sequences:")
    
    attack_types = ["suspicious_network_activity", "malware_hash_detected"]
    for attack_type in attack_types:
        optimal = pm.get_optimal_tool_sequence(attack_type)
        if optimal:
            print(f"  {attack_type}: {' → '.join(optimal)}")


def test_statistics():
    """Test statistics generation"""
    print("\n" + "="*60)
    print("TEST 7: Statistics")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    stats = pm.get_statistics()
    
    print(f"\nTotal Investigations: {stats['total_investigations']}")
    print(f"Average Investigation Time: {stats['average_investigation_time']:.1f}s")
    print(f"Total APIs Configured: {stats['total_apis']}")
    print(f"Total Playbooks: {stats['total_playbooks']}")
    print(f"Last Updated: {stats['last_updated']}")


def test_api_summary_export():
    """Test API summary export"""
    print("\n" + "="*60)
    print("TEST 8: API Summary Export")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    summary = pm.export_api_summary("data/api_summary.md")
    
    print("\nAPI Summary (first 800 chars):")
    print("-" * 60)
    print(summary[:800])
    print("...")
    print("-" * 60)
    print(f"✓ Full summary exported to data/api_summary.md")


def test_real_world_scenario():
    """Test real-world investigation scenario"""
    print("\n" + "="*60)
    print("TEST 9: Real-World Scenario Simulation")
    print("="*60)
    
    pm = ProceduralMemory("data/test_procedural_memory.json")
    
    print("\nScenario: Investigating suspicious IP 192.168.1.100")
    print("-" * 60)
    
    # 1. Get strategy for IP
    strategy = pm.get_api_strategy("ip_address")
    print(f"\n1. Tool Selection Strategy:")
    print(f"   Primary Tool: {strategy['primary']}")
    print(f"   Reason: {strategy['reason']}")
    
    # 2. Get API documentation
    primary_tool = strategy['primary']
    doc = pm.get_api_documentation(primary_tool)
    print(f"\n2. {doc['service_name']} API Details:")
    print(f"   Endpoint: {doc['endpoint']}")
    print(f"   Expected Response Time: {doc['avg_response_time']}s")
    print(f"   Reliability: {doc['reliability_score']:.1%}")
    
    # 3. Simulate execution
    print(f"\n3. Simulating tool execution...")
    pm.update_tool_performance(primary_tool, success=True, response_time=0.95)
    print(f"   ✓ {primary_tool} executed successfully in 0.95s")
    
    # 4. Check if fallback needed
    fallback_tools = strategy['fallback']
    if fallback_tools:
        print(f"\n4. Executing fallback tools for additional context:")
        for fb_tool in fallback_tools[:2]:
            fb_doc = pm.get_api_documentation(fb_tool)
            pm.update_tool_performance(fb_tool, success=True, response_time=1.3)
            print(f"   ✓ {fb_tool} executed successfully")
    
    # 5. Get investigation playbook
    playbook = pm.get_playbook("suspicious_network_activity")
    print(f"\n5. Following Investigation Playbook:")
    print(f"   Priority: {playbook['priority']}")
    print(f"   Estimated Time: {playbook['estimated_time']}")
    
    # 6. Complete investigation
    total_time = 425.3
    pm.record_successful_investigation(
        tool_sequence=[primary_tool] + fallback_tools[:2],
        attack_type="suspicious_network_activity",
        investigation_time=total_time
    )
    print(f"\n6. Investigation Complete:")
    print(f"   Total Time: {total_time}s")
    print(f"   Tools Used: {3}")
    print(f"   ✓ Results recorded in procedural memory")


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("PROCEDURAL MEMORY TEST SUITE")
    print("="*60)
    
    try:
        pm = test_initialization()
        test_api_strategies()
        test_api_documentation()
        test_playbooks()
        test_performance_learning()
        test_investigation_recording()
        test_statistics()
        test_api_summary_export()
        test_real_world_scenario()
        
        print("\n" + "="*60)
        print("ALL TESTS PASSED ✓")
        print("="*60)
        
        # Final statistics
        print("\nFinal Statistics:")
        stats = pm.get_statistics()
        print(f"  Total Investigations: {stats['total_investigations']}")
        print(f"  Average Time: {stats['average_investigation_time']:.1f}s")
        print(f"  APIs Configured: {stats['total_apis']}")
        print(f"  Playbooks Available: {stats['total_playbooks']}")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_all_tests()
