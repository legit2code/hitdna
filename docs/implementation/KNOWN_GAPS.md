# Known Gaps Checkpoint (Phase P00 / P01)

**Architecture Version:** 5.0.0  
**Pack Version:** 6.0.0  

---

## Controlled Technical Gaps

1. **Third-Party Research Provider Credentials (P02 / P11):**
   - External Billboard, Spotify, and Genius API keys are unconfigured in initial development sandbox.
   - Handled via typed epistemic state `NOT_CONFIGURED` without crashing.

2. **Persistence Storage Tier (P03 - P05):**
   - Cloud Firestore and Cloud Storage bindings will be established in P03–P05.
   - In-memory foundation repository is currently active for platform health testing.

3. **External AI Inference Provider (P33 - P38):**
   - Server-side Gemini API client requires `GEMINI_API_KEY` configuration for live generation phases.
   - Isolated behind server proxy; generation engine remains locked until P33.
