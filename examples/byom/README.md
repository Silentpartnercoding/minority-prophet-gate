# Bring your own mess fixtures

Give your coding agent the repository and say:

> Read `AGENT-QUICKSTART.md`. Run the included case, create adversarial variants,
> and give me the generated privacy-safe feedback JSON. Do not connect a real
> runtime or include secrets.

`messy-evidence.jsonl` contains copied SAFE voices, one invalid forgery, and two
independent UNSAFE roots. `policy.json` binds evaluation to the exact subject.

`shadow-events.jsonl` shows the neutral adapter shape for recorded workflow
events. Each event carries an ID, subject, what the existing workflow actually
did, and the evidence visible at that moment. Shadow mode only reads these
copies; it never calls the workflow.
