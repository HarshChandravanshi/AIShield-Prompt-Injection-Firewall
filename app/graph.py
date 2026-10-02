from typing import TypedDict
from app.firewall import PromptInjectionFirewall
from app.models import ScanRequest, ScanResponse

try:
    from langgraph.graph import StateGraph, END

    class FirewallState(TypedDict, total=False):
        request: ScanRequest
        response: ScanResponse

    def build_graph():
        firewall = PromptInjectionFirewall()

        def scan_node(state: FirewallState):
            return {"response": firewall.scan(state["request"])}

        graph = StateGraph(FirewallState)
        graph.add_node("firewall_scan", scan_node)
        graph.set_entry_point("firewall_scan")
        graph.add_edge("firewall_scan", END)
        return graph.compile()

except ImportError:
    def build_graph():
        return None
