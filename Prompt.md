You are acting as a Senior Distributed Systems Architect with deep expertise in IBM MQ, event-driven systems, and large-scale enterprise messaging optimisation.

📌 Context

I am working on a hackathon problem where we must redesign an existing IBM MQ network architecture used in a large enterprise (banking system with multiple Lines of Business like Consumer, CCIBT, WIM, EFT, etc.).

The current system has:

- Uncontrolled proliferation of Queue Managers
- Multiple Queue Managers per application (undesirable)
- Complex, highly interconnected MQ topology (mesh-like)
- Redundant channels and cyclic dependencies
- Poor scalability and difficult maintenance

📂 Dataset

I will provide a CSV dataset (~16,000 rows) with the following fields:

- LOB (Line of Business)
- Application
- Queue Manager Name
- Local Queue
- Remote Queue Manager
- Channel
- Other metadata

This dataset represents the full MQ communication topology.

---

📚 Research Papers (Attached)

Use these as primary references:

1. IBM MQ Messaging Optimisation Paper (focus on routing + topology)
2. Enterprise Integration Patterns (Hohpe & Woolf)
3. Additional MQ scalability / benchmarking papers (if needed)

---

🎯 Your Task (Think deeply before answering)

Step 1: Problem Diagnosis

- Analyse the dataset as a graph (nodes = queue managers, edges = channels)
- Identify:
  - Redundant queue managers
  - Applications using multiple queue managers
  - Cycles and strongly connected components
  - High-degree nodes (hotspots)
  - Inefficient routing paths (multi-hop chains)
- Quantify current complexity using:
  - Node count (N)
  - Edge count (E)
  - Average path length (H)
  - Graph density
  - Degree variance
- Propose a formal complexity function

---

Step 2: Pattern Mapping (VERY IMPORTANT)

Map the existing architecture to known patterns:

- Point-to-Point
- Publish-Subscribe
- Request-Reply
- Anti-patterns (Mesh chaos, uncontrolled federation)

Explain:

- Where the system violates best practices
- Where it aligns with known patterns (if any)

---

Step 3: Target Architecture Design

Design an improved architecture using research-backed principles:

Constraints:

- One Application → One Queue Manager
- No loss of functionality (all communication paths must remain possible)
- Must be scalable and maintainable

Explore and compare:

- Hub-and-Spoke model
- Domain-based clustering (per LOB)
- Hybrid model (Hub + Domain)
- Gateway Queue Managers

Output:

- New graph structure
- Justification of design choices

---

Step 4: Graph Transformation

- Convert the original graph → optimised graph
- Ensure:
  - Functional equivalence (reachability preserved)
  - Reduced complexity
- Generate:
  - New CSV schema
  - Mapping from old → new system

---

Step 5: Complexity Comparison

Compute:

- Old vs New complexity
- % reduction
- Improvements in:
  - Hop count
  - Redundancy
  - Failure domains
  - Maintainability

---

Step 6: Migration Strategy (Enterprise Grade)

Design a safe migration plan:

Phases:

1. Discovery & mapping
2. Parallel system setup
3. Dual-write / dual-routing
4. Gradual cutover
5. Decommissioning

Include:

- Rollback strategy
- Risk mitigation
- Zero downtime approach

---

Step 7: Reliability & Failure Handling

Explain:

- Failure scenarios (queue manager down, channel failure)
- Retry strategies
- Dead letter queues
- Circuit breaker patterns

---

Step 8: Final Output Format

Provide:

1. Clear architecture diagrams (textual if needed)
2. Before vs After comparison
3. Metrics table
4. Key insights for presentation

---

⚠️ Important Instructions

- DO NOT give a generic answer
- Perform deep structural reasoning
- Treat this as a real enterprise system redesign
- Prioritise clarity + correctness + practicality
- Justify every architectural decision

---

🚀 Goal

The final solution should be:

- Research-backed
- Measurable (quantified improvements)
- Enterprise-ready
- Hackathon-winning quality
