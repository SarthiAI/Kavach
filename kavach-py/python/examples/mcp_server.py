"""
Example: MCP Server with Kavach

Shows how to protect an MCP server's tool handlers with Kavach.
Every tool call is evaluated by the Rust engine before execution.

Install:
    pip install kavach mcp

Run:
    python example_mcp_server.py
"""

from kavach import Gate, McpKavachMiddleware

# ── 1. Set up the gate ────────────────────────────────────────────

POLICIES = """
[[policy]]
name = "agent_read_orders"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "read_order" },
    { rate_limit = { max = 100, window = "1h" } },
]

[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 20, window = "1h" } },
]
"""

gate = Gate.from_toml(
    POLICIES,
    invariants=[("max_single_refund", "amount", 50_000.0)],
    max_session_actions=500,
)

kavach = McpKavachMiddleware(gate)


# ── 2. Your tool handlers ────────────────────────────────────────

def read_order(order_id: str) -> dict:
    return {"order_id": order_id, "amount": 2499.00, "status": "delivered"}


def issue_refund(order_id: str, amount: float) -> dict:
    print(f"  >> Processing refund: ₹{amount} for {order_id}")
    return {"refund_id": "ref_001", "amount": amount, "status": "processed"}


# ── 3. Simulate tool calls ───────────────────────────────────────

def handle_tool_call(tool_name: str, params: dict, caller_id: str = "support-bot"):
    """Simulate an MCP tool call with Kavach gating."""
    print(f"\nTool: {tool_name} | Params: {params}")

    # Evaluate through Rust engine
    verdict = kavach.evaluate_tool_call(
        tool_name=tool_name,
        params=params,
        caller_id=caller_id,
        caller_kind="agent",
        roles=["support"],
        session_id="session_001",
    )

    if verdict.is_permit:
        # Gate allowed, execute the tool
        if tool_name == "read_order":
            result = read_order(params["order_id"])
        elif tool_name == "issue_refund":
            result = issue_refund(params["order_id"], params["amount"])
        else:
            result = {"error": "unknown tool"}
        print(f"  ✓ PERMITTED, result: {result}")
    elif verdict.is_refuse:
        print(f"  ✗ REFUSED, [{verdict.code}] {verdict.evaluator}: {verdict.reason}")
    elif verdict.is_invalidate:
        print(f"  ⊘ INVALIDATED, {verdict.reason}")
        kavach.invalidate_session("session_001")


# ── 4. Run scenarios ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Kavach Python MCP Example ===")

    # Should permit
    handle_tool_call("read_order", {"order_id": "ORD-7890"})

    # Should permit (under ₹5,000 limit)
    handle_tool_call("issue_refund", {"order_id": "ORD-7890", "amount": 500.0})

    # Should REFUSE (over ₹5,000 agent limit)
    handle_tool_call("issue_refund", {"order_id": "ORD-7890", "amount": 25_000.0})

    # Should REFUSE (no policy for this tool, default deny)
    handle_tool_call("delete_customer", {"customer_id": "cust_456"})

    print("\n=== Done ===")
