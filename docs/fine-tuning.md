# Fine-Tuning LLM4Decompile

Fine-tune LLM4Decompile on your captured training pairs to improve decompilation quality for specific game binaries and coding patterns.

## Training Data

### Collection

Training pairs are captured during RE work via the decompiler's `--save` flag:

```bash
# Save a verified decompilation
python -m retools.decompiler binary.exe 0x401000 --save my_project

# Save hand-corrected C
python -m retools.decompiler binary.exe 0x401000 --save my_project --save-from corrected.c
```

Pairs accumulate in `patches/<project>/training_pairs.jsonl`.

### Format

Each JSONL line contains:

```json
{
  "input": "# This is the assembly code:\n<assembly>\n# What is the source code?\n",
  "output": "<C code>",
  "metadata": {"binary": "game.exe", "va": "0x401000", "backend": "pdg", "timestamp": "2026-03-14T..."}
}
```

### Data Quality — Name Hallucination

LLM4Decompile produces structurally correct C but **fabricates names**. Function names, variable names, and sometimes types are invented by the model with no basis in the binary.

Before including `llm4d`-generated output in training data:
- **Replace hallucinated function names** with KB-known names
- **Replace hallucinated variable names** with RE-informed names
- **Fix wrong types** (e.g., `double` when the binary uses `float`, or `int` for pointer-sized values)

Uncorrected `llm4d` output reinforces hallucination. Corrected output teaches the model to produce accurate names — this is the highest-value training data you can capture.

Preferred capture strategies (best to worst):
1. `--save-from corrected.c` — hand-corrected C with accurate names and types
2. `--save` with `pdg --types kb.h` — r2ghidra output enriched with KB names (accurate but verbose)
3. `--save` with raw `llm4d` — only if names happen to be reasonable (rare)

### Preparation

Merge all project data and strip metadata for training:

```bash
# Merge projects
cat patches/*/training_pairs.jsonl > combined.jsonl

# Convert to LLaMA-Factory format (strip metadata)
python -c "
import json, sys
for line in open('combined.jsonl'):
    d = json.loads(line)
    print(json.dumps({'instruction': '', 'input': d['input'], 'output': d['output']}))
" > train.jsonl

# Count pairs
wc -l train.jsonl
```

Aim for 500+ pairs before fine-tuning. More is better, but quality matters most.

### Train/Validation Split

Hold out ~10% for validation:

```bash
shuf train.jsonl > shuffled.jsonl
head -n -50 shuffled.jsonl > train_split.jsonl
tail -n 50 shuffled.jsonl > val_split.jsonl
```

## Fine-Tuning with LLaMA-Factory

### Install

```bash
git clone https://github.com/hiyouga/LLaMA-Factory.git
cd LLaMA-Factory
pip install -e ".[torch,metrics]"
```

### Register Dataset

Add to `data/dataset_info.json`:

```json
{
  "decompile_finetune": {
    "file_name": "/path/to/train_split.jsonl",
    "columns": {
      "prompt": "input",
      "response": "output"
    }
  }
}
```

### LoRA Configuration

Create `configs/decompile_lora.yaml`:

```yaml
model_name_or_path: LLM4Binary/llm4decompile-22b-v2
stage: sft
do_train: true
finetuning_type: lora
lora_rank: 16
lora_alpha: 32
lora_target: all
dataset: decompile_finetune
template: default
cutoff_len: 4096
max_samples: 10000
per_device_train_batch_size: 1
gradient_accumulation_steps: 8
learning_rate: 2.0e-5
num_train_epochs: 3
lr_scheduler_type: cosine
warmup_ratio: 0.1
bf16: true
output_dir: output/decompile-lora
logging_steps: 10
save_steps: 100
```

### Launch Training

```bash
llamafactory-cli train configs/decompile_lora.yaml
```

On a single GPU (RTX 5090 32GB), expect ~1-2 hours for 1000 pairs at 3 epochs.

## Converting to GGUF for Ollama

### Merge LoRA Weights

```bash
llamafactory-cli export \
  --model_name_or_path LLM4Binary/llm4decompile-22b-v2 \
  --adapter_name_or_path output/decompile-lora \
  --template default \
  --finetuning_type lora \
  --export_dir output/decompile-merged
```

### Convert to GGUF

```bash
git clone https://github.com/ggml-org/llama.cpp.git
cd llama.cpp

python convert_hf_to_gguf.py /path/to/output/decompile-merged \
  --outfile decompile-22b-ft.gguf --outtype f16

# Quantize to Q8_0 (fits 5090's 32GB)
./llama-quantize decompile-22b-ft.gguf decompile-22b-ft-Q8_0.gguf Q8_0
```

### Load in Ollama

Create a `Modelfile`:

```
FROM ./decompile-22b-ft-Q8_0.gguf
```

Import and test:

```bash
ollama create llm4decompile-ft -f Modelfile
python -m retools.decompiler binary.exe 0x401000 --backend llm4d -m llm4decompile-ft
```

## Iteration

After fine-tuning:

1. Test on functions the base model struggled with
2. Compare output quality against the base model
3. Continue capturing pairs with the fine-tuned model
4. Re-fine-tune periodically as the dataset grows

Each iteration improves the model's understanding of your target binaries' compiler patterns, calling conventions, and data structures.
