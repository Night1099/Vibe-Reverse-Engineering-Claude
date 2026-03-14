---
name: training-capture
description: Capture (assembly, C) training pairs during reverse engineering for fine-tuning LLM4Decompile. Use when verifying or correcting decompiled output.
---

# Training Data Capture for LLM4Decompile

Capture verified (assembly, C) pairs as you work. Each pair improves future fine-tunes of the LLM4Decompile model.

## When to Capture

- After verifying a decompilation is correct (any backend)
- After hand-correcting decompiler output into clean C
- After reconstructing a function from scratch during RE work

Skip: trivial stubs, single-instruction wrappers, functions shorter than ~5 instructions.

## Workflow

### Verified decompilation (output is already correct)

Decompile normally, review the output, then re-run with `--save`:

```
python -m retools.decompiler binary.exe 0x401000 --types patches/proj/kb.h --save proj
```

This extracts the `pdf` assembly and pairs it with the decompiler's C output.

### Hand-corrected C (you fixed the output)

Save your corrected version to a file, then:

```
python -m retools.decompiler binary.exe 0x401000 --save proj --save-from corrected.c
```

This pairs the assembly with your corrected C instead of the decompiler output.

## Name Hallucination

LLM4Decompile fabricates function and variable names. The code structure and logic are usually correct, but names like `nanos_proj` or `step_index` are invented — they have no basis in the binary.

**Before saving `llm4d` output as training data:**
1. Replace hallucinated function names with KB-known names (from `kb.h`)
2. Replace hallucinated variable names with meaningful ones based on your RE understanding
3. Fix hallucinated types (e.g., `double` when the binary uses `float`)

**Best practice:** Use `llm4d` to understand structure, then save a corrected version via `--save-from`:

```
# 1. Decompile with llm4d to understand the function
python -m retools.decompiler binary.exe 0x401000 --backend llm4d -m MHKetbi/llm4decompile-22b-v2:q8_0

# 2. Also decompile with pdg for accurate names/types
python -m retools.decompiler binary.exe 0x401000 --types patches/proj/kb.h

# 3. Merge the best of both into corrected.c, then save
python -m retools.decompiler binary.exe 0x401000 --save proj --save-from corrected.c
```

Alternatively, `pdg` output with `--types` has accurate names from the KB and is safe to `--save` directly when correct.

## Quality Guidelines

High-value captures (prioritize these):
- Functions where LLM4Decompile struggled but you know the correct answer
- Struct-heavy code with named fields and types from the KB
- Functions with KB-enriched assembly (named callees, globals, typed args)
- Corrected `llm4d` output with hallucinated names fixed — teaches the model better naming

Low-value (skip unless nothing better):
- Trivial getters/setters
- Functions the LLM already handles well
- Raw `pdc` output without review (it's barely above assembly)
- Uncorrected `llm4d` output with hallucinated names — reinforces bad naming

## Storage

Training pairs are stored in `patches/<project>/training_pairs.jsonl` (git-ignored). Each line is a JSON object:

```json
{
  "input": "# This is the assembly code:\n<pdf disassembly>\n# What is the source code?\n",
  "output": "<decompiled or corrected C>",
  "metadata": {"binary": "game.exe", "va": "0x401000", "backend": "pdg", "timestamp": "..."}
}
```

## The Flywheel

```
Decompile → Verify/Correct → Capture pair → Fine-tune → Better decompilation
```

Each captured pair makes the next fine-tune better, which means less correction needed, which means faster RE work. Prioritize capturing the functions where the model struggles most — those have the highest training value.

## Fine-Tuning

See `docs/fine-tuning.md` for the full pipeline: data preparation, LoRA training, GGUF conversion, and loading the fine-tuned model in Ollama.
