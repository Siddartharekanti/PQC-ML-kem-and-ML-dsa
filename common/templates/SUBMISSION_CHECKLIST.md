# Final Submission Checklist (all problem statements)

- [ ] Repository (GitHub or Hugging Face Space) is public or shared with the organizers, and the link has been submitted
- [ ] README follows `common/templates/README_template.md`, with exact setup and run commands
- [ ] `requirements.txt` (or equivalent) with pinned versions
- [ ] `platform_A_info.json` committed; `platform_runs.jsonl` committed if Platform B was used
- [ ] No self-implemented cryptographic primitives; a vetted library is used and named
- [ ] Automated tests with expected behaviour and recorded results
- [ ] Raw results (CSV/JSON) and the scripts that produced every table and figure
- [ ] Baseline identified and compared
- [ ] Technical report (`report.md` or PDF), including limitations
- [ ] PS-P1: all of SECURITY_TESTS.md T1–T9 addressed; ≥10 handshakes; three official payloads
- [ ] PS-P2: `run_inventory.py --input --output` works offline on `inventory_dev.csv`; `evaluate.py` output included; baseline compared
- [ ] PS-P3: all CORE algorithms on Platforms A and B; correctness before timing; ≥3 charts; ≥2 deployment scenarios
- [ ] Platform D (optional): `platform_D.md` included if attempted
- [ ] A teammate who did not write the code has re-run the README from a clean clone
