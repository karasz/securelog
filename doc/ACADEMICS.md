# SecureLog Academic Background

## Primary Reference

SecureLog implements the **Dual MAC Private‑Verifiable Scheme** (Section 4) from:

> **"A New Approach to Secure Logging"**  
> Di Ma and Gene Tsudik  
> University of California, Irvine  
> ACM Transactions on Storage (TOS) 5(1):2, March 2009  
> DOI: [10.1145/1502777.1502779](https://doi.org/10.1145/1502777.1502779)

### Accessible Copies

- [IACR ePrint 2008/185](https://eprint.iacr.org/2008/185.pdf) — free preprint  
- [ACM Digital Library](https://dl.acm.org/doi/pdf/10.1145/1502777.1502779) — final publication  
- [Semantic Scholar](https://www.semanticscholar.org/paper/A-new-approach-to-secure-logging-Ma-Tsudik/420e32d7d280b4a4247bcc9ace03fdb59635df99) — alternate sources

## Paper Overview

The paper addresses core challenges of secure logging:

1. **Forward Security** — protecting historic entries after compromise.  
2. **Truncation Detection** — guaranteeing detection of deleted suffixes.  
3. **Verifier Independence** — letting semi‑trusted auditors verify without collusion.  
4. **Delayed Detection Attacks** — defending against malicious verifiers who tamper before the trusted authority inspects the log.

The Dual MAC protocol solves these issues by combining two evolving MAC chains (`μ_V` and `μ_T`) driven by independent key schedules (`A_i`, `B_i`). Semi‑trusted verifiers can validate `μ_V` locally, while the trusted server performs an authoritative check against `μ_T`, catching tampering introduced by verifiers.

## Prior Work

The scheme builds on earlier secure logging research, notably:

- **Schneier & Kelsey (1999)** — forward‑secure logging with single MAC chains.  
- **Bellare & Yee (1997)** — forward‑secure sequential aggregate MACs.  
- **Waters, Balfanz, Durfee & Smetters (2002)** — hash‑chain secure audit logs.

Dual MAC addresses the delayed detection weakness inherent in single‑chain approaches: even if the verifier colludes with an attacker, the trusted server’s chain exposes inconsistencies.
