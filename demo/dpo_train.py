import os, time, json, random, glob
os.environ.setdefault("HF_HUB_OFFLINE", "0")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
STEPS = int(os.environ.get("STEPS", "20"))
MAXSEQ = int(os.environ.get("MAXSEQ", "256"))
BATCH = int(os.environ.get("BATCH", "2"))
COORD = os.environ.get("COORD", "/coord")
MODEL = os.environ.get("MODEL", "unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit")
ARM = os.environ.get("ARM", "?")
FORK = os.environ.get("FORK", "0") == "1"
LID = os.environ.get("LEARNER_ID", "0")
BETA = float(os.environ.get("DPO_BETA", "0.1"))

def emit(lid, **kw):
    kw.update(lid=str(lid), arm=ARM, method="dpo", t=round(time.time(), 3))
    with open(f"{COORD}/learner_{lid}.jsonl", "a") as f:
        f.write(json.dumps(kw) + "\n")

# Resolve the model to its local snapshot so loading never hits the hub.
_snaps = sorted(glob.glob(os.path.join(
    os.environ.get("HF_HOME", os.path.expanduser("~/hf")), "hub",
    "models--" + MODEL.replace("/", "--"), "snapshots", "*")))
if _snaps:
    MODEL = _snaps[-1]
    os.environ["HF_HUB_OFFLINE"] = "1"

from unsloth import FastLanguageModel
import torch
t0 = time.time()
model, tok = FastLanguageModel.from_pretrained(
    MODEL, max_seq_length=MAXSEQ, load_in_4bit=True, dtype=None)
model = FastLanguageModel.get_peft_model(
    model, r=16, lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth", random_state=0)
if tok.pad_token is None:
    tok.pad_token = tok.eos_token
torch.cuda.synchronize()
load_ms = (time.time() - t0) * 1000

from datasets import Dataset
from trl import DPOTrainer, DPOConfig


def make_prefs(seed, n):
    """Synthetic arithmetic preference pairs: 'chosen' is the correct answer,
    'rejected' is a plausible-but-wrong one. A real DPO signal (prefer correct)
    with a distinct per-learner shard via the seed."""
    r = random.Random(seed)
    rows = []
    for _ in range(n):
        a, b = r.randint(1, 20), r.randint(1, 20)
        prompt = f"### Q: what is {a}+{b}?\n### A:"
        chosen = f" {a + b}"
        rejected = f" {a + b + r.choice([-2, -1, 1, 2, 3])}"
        rows.append({"prompt": prompt, "chosen": chosen, "rejected": rejected})
    return Dataset.from_list(rows)


def run_dpo(lid, steps):
    seed = (int(lid) if str(lid).isdigit() else 0) + 100
    ds = make_prefs(seed, max(64, BATCH * steps))
    cfg = DPOConfig(
        per_device_train_batch_size=BATCH, max_steps=steps, learning_rate=5e-5,
        logging_steps=max(1, steps // 4), optim="adamw_8bit", seed=42,
        output_dir=f"/root/dpo{lid}", report_to=[], beta=BETA,
        max_length=MAXSEQ, max_prompt_length=MAXSEQ // 2,
        remove_unused_columns=False, warmup_steps=1,
    )
    FastLanguageModel.for_training(model)
    # ref_model=None: with a PEFT/LoRA policy, DPO uses the adapter-disabled
    # base as the implicit frozen reference — no second model copy. This is the
    # smolvm --share-weights fit: the frozen base (=reference) is shared, each
    # fork trains only its own LoRA policy.
    tr = DPOTrainer(model=model, ref_model=None, args=cfg,
                    train_dataset=ds, processing_class=tok)
    tr.train()
    losses = [h["loss"] for h in tr.state.log_history if "loss" in h]
    return losses


# FORK mode: golden loads once, warms the DPO path, waits at a barrier; the host
# forks N share-weights clones; each resumes here and claims a distinct id.
if FORK:
    if os.environ.get("GOLDEN_WARMUP", "1") == "1":
        # One DPO step in the golden exercises the training write-path so the
        # daemon marks touched chunks private (see qlora_train GOLDEN_WARMUP).
        run_dpo("warm", 1)
        torch.cuda.synchronize()
    with open(f"{COORD}/golden_ready", "w") as f:
        f.write(str(round(load_ms)))
    while not os.path.exists(f"{COORD}/go"):
        time.sleep(0.2)
    claimed = None
    for k in range(int(os.environ.get("NSLOTS", "64"))):
        try:
            fd = os.open(f"{COORD}/claim_{k}", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            claimed = k
            break
        except FileExistsError:
            continue
    LID = str(claimed)
LID = str(LID)

emit(LID, event="ready", load_ms=round(load_ms))
t = time.time()
losses = run_dpo(LID, STEPS)
dur = time.time() - t
toks = STEPS * BATCH * MAXSEQ
emit(LID, event="done", train_s=round(dur, 2), tok_s=round(toks / dur),
     step_ms=round(dur / STEPS * 1000), loss0=round(losses[0], 4),
     lossN=round(losses[-1], 4),
     peak_gb=round(torch.cuda.max_memory_allocated() / 1e9, 2))
print(f"DPO LEARNER {LID} [{ARM}] DONE load={load_ms:.0f}ms "
      f"loss {losses[0]:.3f}->{losses[-1]:.3f} tok/s={toks/dur:.0f} "
      f"peak={torch.cuda.max_memory_allocated()/1e9:.1f}GB", flush=True)
