# ONE-Q Stranger Verification Challenge

You are the control group. We claim the verifier accepts the VALID
release and rejects all four FORGERIES. Do not trust us: run it.

    ./verify.sh          # or .\verify.ps1 on Windows

Requires Python 3.10+ and numpy (`pip install numpy`). ~2 minutes.

Then: publish your UNEDITED log, fill ATTESTATION_TEMPLATE.json,
sign it with any key you control, and report anything ambiguous —
an ambiguity report is as valuable as the attestation.

What each forgery is (spoilers): FORGERIES/WHAT_EACH_FORGERY_IS.json
