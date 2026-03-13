---
name: re-context
description: Context-aware reverse engineering workflow. Routes retools/livetools output through context-mode sandbox to save context window, indexes discoveries per game project into FTS5 knowledge base, and enables cross-session recall of RE findings.
---

# RE Context Integration

Route all reverse engineering tool output through context-mode to preserve context window and build a searchable knowledge base per game project.

## Routing RE Tools Through Sandbox

All `retools` and `livetools` commands produce large output (decompiled C, disassembly, string tables, trace data). **Always run them via `ctx_execute`** instead of raw Bash:

```
ctx_execute(language: "shell", code: "cd D:/GIT/Vibe-Reverse-Engineering && python -m retools.decompiler binary.exe 0x401000 --types patches/project/kb.h")
```

This keeps raw decompilation/disassembly out of the context window. Only your printed summary enters context.

### What to summarize after sandbox execution

After running an RE tool in the sandbox, state:
1. **What the function/data does** (one sentence)
2. **Key addresses** -- callees, globals, struct offsets discovered
3. **KB updates needed** -- new function signatures, struct fields, globals to add

## Indexing Discoveries

When you make a significant discovery about a game binary, index it so future sessions can recall it:

```
ctx_index(content: "## 0x0057519E - SetFrustumCulling\nDisables frustum culling by forcing the cull flag check to always pass.\nCallees: 0x004A2000 (GetRenderConfig), 0x005751E0 (ApplyCullMask)\nStruct: [ecx+0x54] = float cull_distance\nProject: mb_warband", title: "mb_warband/SetFrustumCulling")
```

### What to index

- Function identifications: address, name, purpose, calling convention, key args
- Struct reconstructions: field offsets, types, usage context
- Globals: address, name, type, how it's used
- Patch logic: what was patched, why, what bytes changed
- Vtable mappings: class name, slot offsets, method purposes
- Call chains: sequences of functions that implement a feature
- Data flow: how values propagate through the code (e.g., "config float read at 0xA6F1E8, passed through 0x575000, used in frustum check at 0x57519E")

### Naming convention for indexed content

Use `project_name/topic` as the title:
- `mb_warband/frustum_culling`
- `mb_warband/camera_system`
- `mb_warband/render_pipeline`
- `mb_warband/input_handling`

## Recalling Past Findings

Before starting work on a game, search for prior discoveries:

```
ctx_search(queries: ["mb_warband render", "mb_warband camera", "mb_warband struct"])
```

Use `ctx_batch_execute` when you need to run multiple RE tools AND search prior findings in one call:

```
ctx_batch_execute(
  commands: [
    {"language": "shell", "code": "cd D:/GIT/Vibe-Reverse-Engineering && python -m retools.decompiler binary.exe 0x401000 --types patches/mb_warband/kb.h"},
    {"language": "shell", "code": "cd D:/GIT/Vibe-Reverse-Engineering && python -m retools.xrefs binary.exe 0x401000"}
  ],
  queries: ["mb_warband 0x401000", "mb_warband callers"]
)
```

## Per-Project Progress Tracking

Each game project lives in `patches/<project_name>/`. When starting a new RE session:

1. **Search** prior indexed findings for the project
2. **Read** the existing `kb.h` to see accumulated type knowledge
3. **Continue** from where the last session left off

When ending a session or reaching a milestone:

1. **Index** all new discoveries made during the session
2. **Update** `kb.h` with new function signatures, structs, globals
3. **Summarize** what was learned and what questions remain (index this too)

### Session summary template

Index a session summary after significant progress:

```
ctx_index(content: "## Session Summary - mb_warband - 2026-03-13\n\n### Discovered\n- 0x57519E: frustum cull check, uses [ecx+0x54] as distance\n- 0xA6F1E8: global float, far_plane_distance config value\n- Vtable at 0x85E0E4: CRenderScene class (RTTI confirmed)\n\n### Patches Built\n- DisableFrustumCull.asi: NOPs the cull branch at 0x57519E+0x2A\n\n### Open Questions\n- What controls the LOD transition distances?\n- Who writes to [ecx+0x54]?", title: "mb_warband/session_2026-03-13")
```

## Decision Guide -- When to Use What

| Situation | Tool |
|-----------|------|
| Running any retools/livetools command | `ctx_execute` (shell) |
| Running multiple RE commands at once | `ctx_batch_execute` (commands) |
| Looking up prior findings for a project | `ctx_search` (queries) |
| Recording a function identification | `ctx_index` (content + title) |
| Recording a struct reconstruction | `ctx_index` (content + title) |
| Recording a patch and its rationale | `ctx_index` (content + title) |
| Starting work on a game | `ctx_search` + read `kb.h` |
| Finishing a session | `ctx_index` session summary + update `kb.h` |
