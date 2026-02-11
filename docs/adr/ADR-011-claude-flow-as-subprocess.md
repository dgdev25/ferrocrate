# ADR-011: claude-flow as Subprocess

## Status

**Accepted**

## Context

FerroCrate's AI layer includes integration with claude-flow and agentic-flow for advanced multi-agent orchestration and complex diagnostics.

**claude-flow Characteristics:**
- TypeScript implementation (13.8K GitHub stars)
- Active upstream development
- MCP (Model Context Protocol) support
- 500K+ user community

**Integration Options:**

| Option | Latency | Complexity | Maintenance |
|--------|---------|------------|-------------|
| Rust rewrite | Low | Very High | Full ownership |
| FFI binding | Medium | High | Version coupling |
| Subprocess (MCP) | Medium | Low | Upstream tracks |
| HTTP API | High | Medium | Network dependency |

**Performance Analysis:**
- TypeScript subprocess startup: ~50-100ms
- MCP message latency: ~1-5ms round-trip
- LLM API latency: 2000-5000ms (dominates everything)

The LLM API latency completely overshadows any TypeScript runtime overhead.

## Decision

**claude-flow and agentic-flow are consumed as TypeScript subprocesses via MCP protocol over stdio. Not compiled into the binary.**

Implementation:
1. **Lazy loading**: Node.js spawned only when complex AI features used (~5% of operations)
2. **MCP protocol**: JSON-RPC over stdin/stdout for structured communication
3. **Version decoupling**: FerroCrate specifies minimum claude-flow version
4. **Graceful degradation**: All core container features work without Node.js

**Binary Tiers:**
- **Minimal**: No Node.js dependency, WASM AI only
- **Standard**: Node.js lazy-loaded on demand
- **Full**: All AI features, pre-warmed subprocess

## Consequences

### Positive

- **Upstream alignment**: Benefit from claude-flow improvements automatically
- **No rewrite debt**: 3-6 months of development saved
- **Community access**: 500K+ user community contributes to upstream
- **Focused Rust**: Rust code focuses on container runtime, not AI orchestration
- **Optional dependency**: Users who don't want Node.js can use Minimal tier

### Negative

- **Node.js dependency**: Full AI features require Node.js installed
- **Subprocess overhead**: ~50ms startup for first AI call
- **Process management**: Must manage subprocess lifecycle

### Neutral

- **Version compatibility**: Must track upstream claude-flow versions

## Alternatives Considered

### Rewrite in Rust

**Pros:**
- Single language codebase
- No Node.js dependency
- Possibly faster startup

**Cons:**
- 3-6 months development time
- Fork from actively-maintained upstream
- Lose future community contributions
- Rust AI ecosystem less mature than TypeScript

**Decision**: Rejected. Cost/benefit analysis in PRD Q9 resolution.

### Native FFI Binding

**Pros:**
- No subprocess overhead
- Shared memory possible

**Cons:**
- Complex build system (Node.js native modules)
- Version coupling between Rust and TypeScript
- Debugging across FFI boundary is difficult

**Decision**: Rejected. MCP protocol is cleaner and more maintainable.

### HTTP API

**Pros:**
- Language agnostic
- Easy debugging

**Cons:**
- Network dependency
- Higher latency
- Requires HTTP server management

**Decision**: Rejected. stdio is simpler and lower latency.

## Implementation Notes

**Subprocess Lifecycle:**
```rust
pub struct ClaudeFlowProcess {
    process: Option<Child>,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ClaudeFlowProcess {
    pub async fn spawn_if_needed(&mut self) -> Result<()> {
        if self.process.is_none() {
            self.process = Some(
                Command::new("node")
                    .arg("claude-flow/dist/mcp-server.js")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()?
            );
        }
        Ok(())
    }

    pub async fn invoke(&mut self, method: &str, params: Value) -> Result<Value> {
        self.spawn_if_needed().await?;
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": uuid::Uuid::new_v4()
        });
        self.stdin.write_all(&serde_json::to_vec(&request)?)?;
        self.stdin.write_all(b"\n")?;
        // Read response...
    }
}
```

**MCP Protocol:**
```json
// Request
{"jsonrpc": "2.0", "method": "swarm/status", "params": {}, "id": "uuid"}

// Response
{"jsonrpc": "2.0", "result": {"status": "active", "agents": 5}, "id": "uuid"}
```

**Version Check:**
```rust
const MIN_CLAUDE_FLOW_VERSION: &str = "2.0.0";

fn check_version(process: &mut ClaudeFlowProcess) -> Result<()> {
    let version = process.invoke("version", json!({})).await?;
    if version < MIN_CLAUDE_FLOW_VERSION {
        return Err(Error::OutdatedDependency(...));
    }
    Ok(())
}
```

## References

- [claude-flow Repository](https://github.com/ruvnet/claude-flow)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [PRD Open Question Q9 Resolution](/docs/product-requirements.md#8-open-questions)
- PRD Requirements: AI-05, AI-08, AI-10
