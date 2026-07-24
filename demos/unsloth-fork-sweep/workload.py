# Demo workload: the golden loads the model and blocks on a GO file; each fork
# claims one task over the shared mount and fine-tunes it. See README.md.
import os, time

os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
GO = "/opt/coord/GO"
MODEL = os.environ.get("SMOLVM_MODEL", "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit")
def mark(m):
    open("/opt/coord/marks.txt", "a").write(f"{time.time():.2f} {m}\n")

t0 = time.time()
from unsloth import FastLanguageModel
model, tok = FastLanguageModel.from_pretrained(MODEL, max_seq_length=256, load_in_4bit=True)
model = FastLanguageModel.get_peft_model(
    model, r=8, lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    use_gradient_checkpointing="unsloth", random_state=42)

# Run fix_untrained_tokens in the golden so clones don't write the embedding
# at trainer setup (recommended for 3+ clones with weight sharing).
from unsloth_zoo.tokenizer_utils import fix_untrained_tokens
from datasets import Dataset
_ds = Dataset.from_list([{"text": f"### Q: {a}+{b}?\n### A: {a+b}"}
                         for a in range(1, 13) for b in range(1, 13)])
FastLanguageModel.for_training(model)
fix_untrained_tokens(model, tok, _ds, [], eps=1e-16)
import torch; torch.cuda.synchronize()
FastLanguageModel.for_inference(model)
mark(f"READY load={time.time()-t0:.1f}s model={MODEL}")

while not os.path.exists(GO):
    time.sleep(0.2)  # golden freezes here; forks are taken during this wait
t_go = time.time()

# Claim one task per fork (O_EXCL on the shared mount).
TASKS = [("add", "+", lambda a, b: a + b),
         ("mul", "*", lambda a, b: a * b),
         ("sub", "-", lambda a, b: a - b)]
idx = None
for i in range(len(TASKS)):
    try:
        fd = os.open(f"/opt/coord/claim_{i}", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd); idx = i; break
    except FileExistsError:
        continue
if idx is None:
    mark("golden idle (all tasks claimed)")
else:
    name, op, fn = TASKS[idx]
    ds = Dataset.from_list([{"text": f"### Q: {a}{op}{b}?\n### A: {fn(a,b)}"}
                            for a in range(1, 13) for b in range(1, 13)])
    from trl import SFTTrainer, SFTConfig
    FastLanguageModel.for_training(model)
    tr = SFTTrainer(model=model, tokenizer=tok, train_dataset=ds, args=SFTConfig(
        per_device_train_batch_size=2, max_steps=int(os.environ.get("SMOLVM_STEPS", "20")),
        learning_rate=3e-4, logging_steps=10, optim="adamw_8bit", seed=42,
        output_dir=f"/root/o{idx}", report_to=[],
        dataset_text_field="text", max_seq_length=256, warmup_steps=2))
    t_train = time.time()
    mark(f"clone[{name}] training after {t_train-t_go:.1f}s")
    tr.train()
    losses = [h["loss"] for h in tr.state.log_history if "loss" in h]
    FastLanguageModel.for_inference(model)
    q = f"### Q: 6{op}7?\n### A:"
    ids = tok(q, return_tensors="pt").to("cuda")
    gen = tok.decode(model.generate(**ids, max_new_tokens=5, do_sample=False)[0],
                     skip_special_tokens=True)[len(q):].strip()
    gen = (gen.split() or [""])[0][:8]  # first token; keep the result file one-line
    ok = gen == str(fn(6, 7))
    open(f"/opt/coord/result_{idx}.txt", "w").write(
        f"{name}|{t_train-t_go:.1f}|{losses[0]:.2f}|{losses[-1]:.2f}|6{op}7|{gen}|{fn(6,7)}|{'PASS' if ok else 'FAIL'}\n")
    mark(f"clone[{name}] done ok={ok}")
