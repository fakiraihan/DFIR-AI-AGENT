import unittest

from modules.agent import DFIRAgent


class FakeLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return ""


class DFIRAgentGraphShapeTest(unittest.TestCase):
    def test_graph_uses_professional_node_names(self):
        agent = DFIRAgent(llm=FakeLLM())

        graph = agent.app.get_graph()
        node_names = set(graph.nodes)

        self.assertEqual(
            {
                "extractor",
                "context",
                "planner",
                "tool_selector",
                "tool_executor",
                "assessor",
                "correlator",
                "reflector",
                "inconclusive",
                "timeline",
                "reporter",
            },
            node_names - {"__start__", "__end__"},
        )
        self.assertNotIn("ioc_extractor", node_names)
        self.assertNotIn("context_only_summary", node_names)
        self.assertNotIn("report_generator", node_names)

    def test_context_path_routes_through_reporter(self):
        agent = DFIRAgent(llm=FakeLLM())

        graph = agent.app.get_graph()
        edges = {(edge.source, edge.target) for edge in graph.edges}

        self.assertIn(("context", "reporter"), edges)
        self.assertNotIn(("context", "__end__"), edges)


if __name__ == "__main__":
    unittest.main()
