import os, time, json, random, glob
t_import0 = time.time()
os.environ.setdefault("HF_HUB_OFFLINE", "0")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
STEPS = int(os.environ.get("STEPS", "40"))
MAXSEQ= int(os.environ.get("MAXSEQ", "512"))
BATCH = int(os.environ.get("BATCH", "2"))
COORD = os.environ.get("COORD", "/coord")
MODEL = os.environ.get("MODEL", "unsloth/Qwen2.5-7B-bnb-4bit")
ARM   = os.environ.get("ARM", "?")
FORK  = os.environ.get("FORK", "0") == "1"
LID   = os.environ.get("LEARNER_ID", "0")
def emit(lid, **kw):
    kw.update(lid=str(lid), arm=ARM, t=round(time.time(), 3))
    with open(f"{COORD}/learner_{lid}.jsonl", "a") as f:
        f.write(json.dumps(kw) + "\n")

# Resolve the model to its LOCAL snapshot directory under HF_HOME so loading
# never touches the HF hub (no online verify, no offline-resolution quirk) —
# identical behavior across native / container / guest.
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
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    use_gradient_checkpointing="unsloth", random_state=0)
FastLanguageModel.for_training(model)
if tok.pad_token is None: tok.pad_token = tok.eos_token
opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=2e-4)
torch.cuda.synchronize()
load_ms = (time.time() - t0) * 1000

# FORK mode: golden loads, signals ready, waits at a barrier. The host forks N
# clones while we wait; each clone resumes here and claims a distinct learner id
# (O_EXCL) so it trains its own data shard.
if FORK:
    # GOLDEN WARMUP (density-fix): run one full training step in the golden
    # BEFORE forking. The daemon shares a weight chunk only if its content
    # still equals the initial H2D upload; running the training path here
    # dirties every chunk the forward/backward/optimizer touches, so those
    # get marked PRIVATE per clone instead of shared read-write (which raced
    # and corrupted at N>=3). The genuinely-frozen base stays shared (dense).
    if os.environ.get("GOLDEN_WARMUP", "1") == "1":
        dummy = torch.randint(0, 1000, (BATCH, MAXSEQ), device="cuda")
        wo = model(input_ids=dummy, labels=dummy); wo.loss.backward()
        opt.step(); opt.zero_grad(set_to_none=True)
        torch.cuda.synchronize()
    with open(f"{COORD}/golden_ready", "w") as f: f.write(str(round(load_ms)))
    while not os.path.exists(f"{COORD}/go"):
        time.sleep(0.2)
    claimed = None
    for k in range(int(os.environ.get("NSLOTS", "64"))):
        try:
            fd = os.open(f"{COORD}/claim_{k}", os.O_CREAT | os.O_EXCL | os.O_WRONLY); os.close(fd)
            claimed = k; break
        except FileExistsError:
            continue
    LID = str(claimed)
LID = str(LID)
# Per-learner data shard: distinct seed -> distinct tokens -> distinct loss
# trajectory (the isolation proof).
random.seed(int(LID) + 100)
vocab = ["alpha","beta","gamma","delta","epsilon","zeta","eta","theta","iota","kappa"]
texts = [f"Learner {LID} sample {i}: " + " ".join(random.choice(vocab) for _ in range(80))
         for i in range(max(64, BATCH * STEPS))]
enc = tok(texts, return_tensors="pt", padding="max_length", truncation=True, max_length=MAXSEQ)
ids = enc.input_ids.cuda()
torch.cuda.synchronize()
emit(LID, event="ready", load_ms=round(load_ms), ready_ms=round((time.time() - t_import0) * 1000))
losses = []; tstep0 = time.time(); n = ids.shape[0]
for step in range(STEPS):
    b = ids[(step * BATCH) % n : (step * BATCH) % n + BATCH]
    if b.shape[0] < BATCH: b = ids[:BATCH]
    out = model(input_ids=b, labels=b)
    out.loss.backward(); opt.step(); opt.zero_grad()
    losses.append(float(out.loss.detach()))
torch.cuda.synchronize()
dur = time.time() - tstep0; toks = STEPS * BATCH * MAXSEQ
peak = torch.cuda.max_memory_allocated() / 1e9
emit(LID, event="done", train_s=round(dur, 2), tok_s=round(toks / dur),
     step_ms=round(dur / STEPS * 1000), loss0=round(losses[0], 3), lossN=round(losses[-1], 3),
     peak_gb=round(peak, 2))
print(f"LEARNER {LID} [{ARM}] DONE load={load_ms:.0f}ms loss {losses[0]:.2f}->{losses[-1]:.2f} "
      f"tok/s={toks/dur:.0f} peak={peak:.1f}GB", flush=True)
