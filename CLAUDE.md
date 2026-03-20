# Vibe Reverse Engineering -- Claude Code Instructions

## Engineering Standards

Every change should make the codebase better, not just make the problem go away. If a solution needs a paragraph to justify why it's not a hack, it's a hack.

### Remove
- **Fixes in the wrong layer**: a guard on a canvas to suppress commits that a model should own. Put the fix where the problem originates.
- **Tolerance inflation**: widening deltas or adding retries to hide flaky behavior. If the value is wrong, find out why.
- **Catch-all exception swallowing**: `try/except Exception: pass` to hide symptoms.
- **Excessive error/null handling**: adding too many error/None "if" checks. If the error is expected, handle it. If unexpected, raise it.
- **God methods**: 200+ line functions doing multiple things. Break into named steps. Focus on cognitive load. Design for fewer indentation levels.
- **Leaky abstractions**: implementation details leaking into layers/modules that should be agnostic of one another.

### Design For
- **Single responsibility**: one component, one job. If you need "and" to describe it, split it.
- **Ownership**: the component that creates the problem owns the fix.
- **Minimal public surface**: expose what consumers need, nothing more.

### Commit to the New Code
- **No legacy fallbacks**: if you replace a system, remove the old one.
- **No dead code**: commented-out blocks, unused imports, orphan functions "just in case". Version control is the safety net.
- **No multiple paths to the same result**: one way to do each thing. If two paths exist, one is wrong.
- **No half-migrations**: finish the job -- update every reference, remove old APIs.

### Smell Tests
- "It works if I add a sleep" -- broken data flow.
- "It works if I read from widget instead of storage" -- the two are out of sync.
- "It passes alone but fails with other tests" -- shared mutable state leaking.
- "I added a flag to skip this code path" -- why does that path run in the first place?

## Code Comments

Each file reads as if it was always designed this way. Comments guide the next developer, not narrate the development journey.

### Remove
- **Implementation backstories**: "We do this because the other day X happened"
- **Obvious narration**: "Create the attribute", "Loop through keys", "Check if valid" -- if the code says it, the comment is noise
- **Debugging breadcrumbs**: "Without this, subsequent tests may see the modifier key as still held"
- **Trial-and-error reasoning**: "We tried X but it caused Y so we do Z instead"

### Keep
- **Non-obvious design decisions**: stated as *what* and *why this design*, not *what happened to us*
- **Tricky invariants**: conditions that would be easy to accidentally break
- **API contracts**: docstrings on public methods with Args, Returns, Raises

### Prefer Instead
- **Rename** a variable or function to be self-explanatory rather than adding a comment
- **Docstrings** on classes and public methods (Google style: `Args:`, `Returns:`, `Raises:`)
- **Type hints** over comments about expected types
- **Short inline comments** on the *why*, never the *what*

---

## Tool Catalog

All tools work on PE binaries (`.exe` and `.dll`). Full tool reference with syntax and examples: @.claude/rules/tool-catalog.md

Always consult the catalog and this decision guide before making any move to take the best decision on what to use with best bang for your buck.

IMPORTANT: Collecting MORE INFORMATION per command run is encouraged over minor snippets of data/output that don't reveal the whole picture.

### Decision Guide

- "What does this function do?" → `decompiler.py` (best), then `disasm.py` + `cfg.py`
- "Decompile with named structs and functions" → `decompiler.py --types`
- "Who calls this function?" → `xrefs.py` (flat) or `callgraph.py --up` (tree)
- "What does this function call?" → `funcinfo.py` (list) or `callgraph.py --down` (tree)
- "Where is this global read/written?" → `datarefs.py`
- "Where is this string/pointer referenced?" → `datarefs.py --imm`
- "Find a string and who uses it" → `search.py strings --xrefs`
- "Where is struct field +0x54 used?" → `structrefs.py`
- "What does this struct look like?" → `structrefs.py --aggregate`
- "What C++ class is this vtable?" → `rtti.py vtable`
- "What type was a caught/thrown exception?" → `rtti.py throwinfo`
- "What DLL functions are exported?" → `search.py exports`
- "Find all instructions using a specific constant" → `search.py insn`
- "Find a mov-immediate near a struct field access" → `search.py insn --near`
- "Find a known byte sequence" → `search.py pattern`
- **"What crashed and what was the error message?"** → `dumpinfo.py diagnose --binary <dll>`
- "What C++ exception type was thrown?" → `dumpinfo.py exception`
- "Which module has frames on the crash stack?" → `dumpinfo.py stackscan <tid> --module <name>`
- "Map all throw sites to error strings in a DLL" → `throwmap.py <dll> list`
- "Match a specific dump against throw sites" → `throwmap.py <dll> match --dump <dmp>`
- "Where is each thread stuck?" → `dumpinfo.py threads`
- "Walk a crashing thread's call stack" → `dumpinfo.py stack <tid>`
- "Is a specific string in the dump memory?" → `dumpinfo.py memscan <pattern>` or `strings --pattern`
- "What memory regions are captured in the dump?" → `dumpinfo.py memmap`
- "Is this function reached at runtime?" → `livetools trace` or `collect`
- "What are the actual register values?" → `livetools trace --read` or `bp` + `regs`
- "How many draw calls happen?" → `livetools dipcnt`
- "Who writes to this memory address?" → `livetools memwatch`
- **"What does the game's full render frame look like?"** → `dx9tracer analyze --summary` + `--render-passes` + `--pipeline-diagram`
- "What shaders does the game use and what constants do they need?" → `dx9tracer analyze --shader-map`
- "Which code set a specific shader constant at draw time?" → `dx9tracer analyze --const-provenance` or `--const-provenance-draw N`
- "What vertex formats does the game use?" → `dx9tracer analyze --vtx-formats`
- "What is the full device state at a specific call?" → `dx9tracer analyze --state-at SEQ` or `--state-snapshot DRAW#`
- "How do registers change across draws? Which are per-object vs frame-global?" → `dx9tracer analyze --const-evolution vs:c0-c8`
- "Does the game use SetTransform or only shader constants for matrices?" → `dx9tracer analyze --transform-calls`
- "How do two draw calls differ?" → `dx9tracer analyze --diff-draws A B`
- "What is the render target dependency graph?" → `dx9tracer analyze --rt-graph`
- "Where is the render loop entry point?" → `dx9tracer analyze --render-loop --resolve-addrs <binary>`
- "Which draw method (DIP/DP) and which shaders account for most draws?" → `dx9tracer analyze --classify-draws`
- "Which state sets are redundant?" → `dx9tracer analyze --redundant`

---

## RTX Remix — DX9 FFP Porting

Full FFP porting workflow, file map, and common pitfalls: @.claude/rules/dx9-ffp-port.md

**When to use**: whenever the user mentions FFP rendering, DX9 shader-to-FFP conversion, RTX Remix compatibility, or building a `d3d9.dll` proxy for a game.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable `ENABLE_SKINNING`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support.

---

## Project Workspace

Use `patches/<project_name>/` (git-ignored) for all project-specific artifacts:
- Knowledge base files (`kb.h`)
- One-off analysis scripts
- ASI patch specs and builds
- Notes, logs, collected trace data

Create the project subfolder on first use.

## Knowledge Base

When reverse engineering a binary, maintain a knowledge base file (`.h`) that accumulates discoveries. Store in `patches/<project>/kb.h`.

**Format:**
```c
// C type definitions (structs, enums, typedefs) -- no prefix
struct Foo { int x; float y; };
enum Mode { MODE_A=0, MODE_B=1 };
typedef unsigned int Flags;

// Function signatures at addresses -- @ prefix
@ 0x401000 void __cdecl ProcessInput(int key);
@ 0x402000 float __thiscall Object_GetValue(Object* this);

// Global variables at addresses -- $ prefix
$ 0x7C5548 Object* g_mainObject
$ 0x7C554C Flags g_renderFlags
```

**When to update the KB:**
- When you identify a function's purpose, add `@ 0xADDR` with a descriptive name and signature
- When you reconstruct a struct (e.g., from `structrefs.py --aggregate`), add the struct definition
- When you identify a global variable via `datarefs.py`, add `$ 0xADDR` with its name and type
- When you identify magic constants, define an enum with named values
- When `rtti.py` reveals a class name, use it in struct/function names

**Always pass `--types <kb_file>` when using `decompiler.py`** so accumulated knowledge improves every decompilation.
