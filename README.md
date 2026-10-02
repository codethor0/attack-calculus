# Attack Calculus (ACN)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23092790.svg)](https://doi.org/10.5281/zenodo.23092790)
[![Release](https://img.shields.io/badge/release-v1.0.0-1f6feb.svg)](https://github.com/codethor0/attack-calculus/releases/tag/v1.0.0)
[![Paper License](https://img.shields.io/badge/paper-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Code License](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0001--6573--385X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0001-6573-385X)

**A Typed, Evidence-Aware State-Transition Calculus for Cross-Domain Cybersecurity Reasoning**

**Thor Thor**<br>
Independent Open-Source Researcher, [THOR-SEC](https://codethor0.github.io/thor-sec/)<br>
ORCID: [0009-0001-6573-385X](https://orcid.org/0009-0001-6573-385X)

> A formal and reproducible framework for representing cybersecurity incidents as typed, evidence-backed state transitions and reasoning across competing evidence-consistent models.

This research was conducted independently on the author's own time and is not sponsored by, affiliated with, or representative of any employer.

## Overview

Attack Calculus Notation (ACN) is a typed, evidence-aware state-transition calculus for cybersecurity reasoning. It provides a compact way to represent **who acted, why, how, against what target, under which state conditions, what changed, and what evidence supports each claim**.

ACN compiles analyst-readable expressions into a guarded predicate-transition model. Under the paper's stated finite-ground and invariant assumptions, the reachability core reduces to typed STRIPS planning. Evidence uncertainty defines a family of admissible models, allowing the analysis to distinguish between compromise that is **possible** in at least one admissible model and compromise that is **necessary** across all admissible models.

The framework also models defensive controls as transformations over the system and searches for low-cost control bundles that block prohibited outcomes while preserving authorized tasks. An AI-agent extension separates influence from authority and measures excess authority using capability subsumption.

## Core Contributions

| Area | Contribution |
| --- | --- |
| Typed state transitions | Explicit actors, intent, mechanism, target, object, channel, guards, and effects |
| Evidence-aware reasoning | Field-level evidence constrains a family of admissible models instead of forcing a single explanation |
| Compromise semantics | Distinguishes possible compromise from necessary compromise across admissible models |
| Defensive synthesis | Selects control bundles that eliminate modeled prohibited outcomes while preserving task utility |
| AI-agent security | Separates influence from authority and models capability-scoped excess authority |
| Reproducibility | Includes an executable reference checker that reproduces the worked-example results |

## Model Pipeline

![ACN pipeline](docs/figures/pipeline.png)

Analyst expressions compile to a guarded predicate-transition model. Evidence determines which models remain admissible, and compromise and defense questions are evaluated over that model family.

## Worked Example

![Worked example](docs/figures/worked-example.png)

The paper includes a synthetic identity-security scenario with two evidence-consistent models. The published checker reproduces the paper's worked-example results, including:

- Robust synthesis across both admissible models selects `{k1, k3}` at cost `3` while preserving all modeled authorized tasks.
- Restricting analysis to model `M1` selects `{k1}` at cost `2`, but that choice does not block compromise in `M2`.
- Attack-only minimization selects `{k2, k3}` at cost `2` and breaks a legitimate maintenance task.

These values validate the paper's formal example. They are not claims of empirical real-world effectiveness.

## AI-Agent Extension

![AI-agent extension](docs/figures/ai-agent-extension.png)

The AI-agent extension treats **influence** and **authority** as separate conditions. A path to a prohibited effect depends not only on whether an agent can be influenced, but also on whether its granted capabilities, policy, resource reachability, and permitted effects authorize that path.

## Reproducibility

The reference checker uses only the Python standard library.

```bash
python3 scripts/acn_checks.py
```

It implements the core worked-example semantics, including valued states, invariants, transition enablement and application, trace execution, independence, exact reachability, possible and necessary compromise, control transformations, robust synthesis, and subsumption-aware excess authority.

## Repository Structure

| Path | Description |
| --- | --- |
| `paper/ACN.pdf` | Published preprint |
| `paper/acn.tex` | LaTeX source; figures are defined in TikZ |
| `paper/abstract.txt` | Plain-text abstract |
| `scripts/acn_checks.py` | Executable reference checker |
| `docs/figures/` | README figures |
| `CITATION.cff` | Citation metadata |
| `CHANGELOG.md` | Release history |

## Build the Paper

```bash
cd paper
pdflatex acn.tex
pdflatex acn.tex
```

## Publication

| Item | Value |
| --- | --- |
| Version | `1.0.0` |
| Publication date | October 1, 2026 |
| DOI | [10.5281/zenodo.23092790](https://doi.org/10.5281/zenodo.23092790) |
| GitHub release | [v1.0.0](https://github.com/codethor0/attack-calculus/releases/tag/v1.0.0) |

### Citation

Thor, T. (2026). *Attack Calculus: A Typed, Evidence-Aware State-Transition Calculus for Cross-Domain Cybersecurity Reasoning* (Version 1.0.0). Zenodo. https://doi.org/10.5281/zenodo.23092790

Machine-readable citation metadata is available in [`CITATION.cff`](CITATION.cff).

## Research Status and Scope

Attack Calculus is a formal specification and falsifiable research program. The current release establishes the notation, semantics, model-family treatment of evidence uncertainty, defensive-synthesis formulation, AI-agent extension, and a reproducible worked example.

It does **not** claim empirical superiority, improved detection accuracy, or operational effectiveness. Those questions require the evaluation program described in the paper.

## Related Work by the Author

Thor, T. (2026). *Mission-Invariant Architecture Morphing: Service-Graph Reconfiguration Against Post-Access Reconnaissance, with Cryptographic Epoch Isolation and Mission-Domain State Continuity* (Version 1.0.0). Zenodo. https://doi.org/10.5281/zenodo.23001045

## Review and Feedback

Corrections, counterexamples, missing prior art, implementation feedback, and formal critiques are welcome. Please open a GitHub issue using the **Review finding** template and identify the relevant section, equation, definition, figure, or claim.

## License

- Paper, LaTeX source, and figures: **CC BY 4.0**
- Reference-checker code: **MIT License**

See [`LICENSE`](LICENSE) and [`paper/LICENSE.md`](paper/LICENSE.md) for details.
