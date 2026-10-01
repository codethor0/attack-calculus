#!/usr/bin/env python3
"""
Reference checker for "Attack Calculus" (ACN).

Implements the core ACN semantics and reproduces every value in the
paper's worked example: valued atoms with exclusivity, invariants,
enablement, application, trace execution, independence, exact
model-relative compromise, possible and necessary compromise over an
evidence-consistent family, controls as model transformations, robust
task-preserving synthesis with worst-case utility, and the
subsumption-aware excess-authority interval.

Validates internal arithmetic and semantics only. Standard library only.
"""
from itertools import combinations
from collections import deque
from fnmatch import fnmatchcase

# ---------------------------------------------------------------- core
# An atom is (predicate, args_tuple, value). A state is a frozenset of atoms.

def atom(p, *args, v=True):
    return (p, tuple(args), v)

def key(a):
    return (a[0], a[1])

class T:
    def __init__(self, tid, actor, pre, add, dele):
        self.tid, self.actor = tid, actor
        self.pre, self.add, self.dele = frozenset(pre), frozenset(add), frozenset(dele)
        assert not (self.add & self.dele), f"{tid}: Add and Del overlap"

def exclusive(state):
    seen = set()
    for a in state:
        if key(a) in seen:
            return False
        seen.add(key(a))
    return True

def holds(state, a):
    return a in state

def make_gamma(implications):
    """Gamma = value exclusivity plus implications (antecedent -> consequent)."""
    def gamma(state):
        if not exclusive(state):
            return False
        return all((not holds(state, x)) or holds(state, y) for x, y in implications)
    return gamma

def nxt(state, t):                                  # Eq. 3
    return frozenset((state - t.dele) | t.add)

def enabled(t, state, gamma):                       # Eq. 4
    return t.pre <= state and gamma(nxt(state, t))

def apply(state, t, gamma):                         # Eq. 5
    assert enabled(t, state, gamma)
    return nxt(state, t)

def end(state, trace, gamma):                       # Eq. 8
    for t in trace:
        if not enabled(t, state, gamma):
            return None
        state = apply(state, t, gamma)
    return state

def independent(t, u, s, gamma):                    # Eq. 10
    return (enabled(t, s, gamma) and enabled(u, s, gamma)
            and enabled(t, apply(s, u, gamma), gamma)
            and enabled(u, apply(s, t, gamma), gamma)
            and apply(apply(s, t, gamma), u, gamma) == apply(apply(s, u, gamma), t, gamma))

def reachable(model, s0, goal, actors=None):
    """Exact reachability over the finite state space (no horizon needed)."""
    ts = [t for t in model["T"] if actors is None or t.actor in actors]
    gamma = model["gamma"]
    seen, q = {s0}, deque([(s0, ())])
    while q:
        s, path = q.popleft()
        if goal <= s:
            return path
        for t in ts:
            if enabled(t, s, gamma):
                n = apply(s, t, gamma)
                if n not in seen:
                    seen.add(n)
                    q.append((n, path + (t.tid,)))
    return None

# ---------------------------------------------------------------- worked example
A, U, SVC = "A", "U", "svc"

base_pre_login_nomfa = [atom("KNOW", A, "cred_U"), atom("MFA", U, v="off"),
                        atom("SESSION", A, v="none")]

def transitions(model_id):
    ts = [
        # attacker
        T("t1_login", A, base_pre_login_nomfa,
          [atom("SESSION", A, v="active")], [atom("SESSION", A, v="none")]),
        T("t2_assume", A,
          [atom("SESSION", A, v="active"), atom("ASSUMABLE", "admin", v="true")],
          [atom("ROLESESS", A, v="active"), atom("AUTH", A, "admin", v="active")],
          [atom("ROLESESS", A, v="none"), atom("AUTH", A, "admin", v="none")]),
        T("t3_read", A,
          [atom("AUTH", A, "admin", v="active"), atom("READGATE", v="open")],
          [atom("KNOW", A, "records")], []),
        T("t5_logout", A, [atom("SESSION", A, v="active")],
          [atom("SESSION", A, v="none")], [atom("SESSION", A, v="active")]),
        # legitimate user U (task q1: maintenance via role assumption with MFA device)
        T("u1_login_mfa", U,
          [atom("MFA", U, v="on"), atom("DEVICE", U), atom("SESSION", U, v="none")],
          [atom("SESSION", U, v="active")], [atom("SESSION", U, v="none")]),
        T("u1_login_nomfa", U,
          [atom("MFA", U, v="off"), atom("SESSION", U, v="none")],
          [atom("SESSION", U, v="active")], [atom("SESSION", U, v="none")]),
        T("u2_assume", U,
          [atom("SESSION", U, v="active"), atom("ASSUMABLE", "admin", v="true")],
          [atom("ROLESESS", U, v="active"), atom("AUTH", U, "admin", v="active")],
          [atom("ROLESESS", U, v="none"), atom("AUTH", U, "admin", v="none")]),
        # backup service (task q2)
        T("b1_backup", SVC,
          [atom("AUTH", SVC, "backup", v="active"), atom("READGATE", v="open")],
          [atom("DONE", "backup")], []),
    ]
    if model_id == "M2":
        # alternative escalation consistent with the evidence: exposed admin key
        ts.append(T("t2b_key", A,
                    [atom("KEY", "admin", v="exposed"), atom("KNOW", A, "admin_key")],
                    [atom("AUTH", A, "admin", v="active")],
                    [atom("AUTH", A, "admin", v="none")]))
    return ts

gamma = make_gamma([
    # role session requires the login session that created it
    (atom("ROLESESS", A, v="active"), atom("SESSION", A, v="active")),
    (atom("ROLESESS", U, v="active"), atom("SESSION", U, v="active")),
])

def s0_for(model_id):
    s = {atom("KNOW", A, "cred_U"), atom("MFA", U, v="off"), atom("DEVICE", U),
         atom("SESSION", A, v="none"), atom("SESSION", U, v="none"),
         atom("ROLESESS", A, v="none"), atom("ROLESESS", U, v="none"),
         atom("AUTH", A, "admin", v="none"), atom("AUTH", U, "admin", v="none"),
         atom("AUTH", SVC, "backup", v="active"),
         atom("ASSUMABLE", "admin", v="true"), atom("READGATE", v="open")}
    if model_id == "M2":
        s |= {atom("KEY", "admin", v="exposed"), atom("KNOW", A, "admin_key")}
    else:
        s |= {atom("KEY", "admin", v="vaulted")}
    return frozenset(s)

FAMILY = {m: {"T": transitions(m), "gamma": gamma} for m in ("M1", "M2")}
S0 = {m: s0_for(m) for m in ("M1", "M2")}
GOAL = frozenset({atom("KNOW", A, "records")})
TASKS = {"q1": ({U}, frozenset({atom("AUTH", U, "admin", v="active")})),
         "q2": ({SVC}, frozenset({atom("DONE", "backup")}))}
ADVERSARY_AND_ENV = None  # compromise ranges over all transitions (conservative)

# ---------------------------------------------------------------- controls
def set_value(state, p, args, v):
    s = {a for a in state if not (a[0] == p and a[1] == args)}
    s.add((p, args, v))
    return frozenset(s)

def k1_mfa(model, s0):      # enforce MFA
    return model, set_value(s0, "MFA", (U,), "on")

def k2_norole(model, s0):   # revoke role assumability
    return model, set_value(s0, "ASSUMABLE", ("admin",), "false")

def k3_key(model, s0):      # rotate and vault the exposed key
    return model, set_value(s0, "KEY", ("admin",), "vaulted")

def k4_gate(model, s0):     # break-glass approval for every database read
    return model, set_value(s0, "READGATE", (), "approval_required")

CONTROLS = {"k1": (k1_mfa, 2), "k2": (k2_norole, 1), "k3": (k3_key, 1), "k4": (k4_gate, 4)}

def apply_bundle(bundle, model, s0):
    for k in sorted(bundle):
        model, s0 = CONTROLS[k][0](model, s0)
    return model, s0

def cost(bundle):
    return sum(CONTROLS[k][1] for k in bundle)

def compromised(bundle, m):
    model, s0 = apply_bundle(bundle, FAMILY[m], S0[m])
    return reachable(model, s0, GOAL) is not None

def utility(bundle, m):
    model, s0 = apply_bundle(bundle, FAMILY[m], S0[m])
    ok = sum(reachable(model, s0, g, actors) is not None for actors, g in TASKS.values())
    return ok / len(TASKS)

def synthesize(models, eta):
    best = None
    for r in range(len(CONTROLS) + 1):
        for b in combinations(sorted(CONTROLS), r):
            safe = all(not compromised(b, m) for m in models)
            u = min(utility(b, m) for m in models)
            if safe and u >= eta:
                cand = (cost(b), b, u)
                if best is None or cand < best:
                    best = cand
    return best

# ---------------------------------------------------------------- authority (Section 9.2)
# capability = (operation, scope); c <= c2 iff same operation and scope of c inside scope of c2
def covers(c2, c):
    """c is subsumed by c2: same operation, and c2's scope pattern matches c's scope."""
    op2, sc2 = c2
    op, sc = c
    return op == op2 and fnmatchcase(sc, sc2)

def req_feasible(H, R):
    return all(any(covers(h, c) for h in H) for c in R)

def excess(H, R, w):
    used = {h for h in H if any(covers(h, c) for c in R)}
    return sum(w[h] for h in H if h not in used)

def main():
    print("== Semantics ==")
    g = FAMILY["M1"]["gamma"]
    s = S0["M1"]
    tr = {t.tid: t for t in FAMILY["M1"]["T"]}
    s1 = apply(s, tr["t1_login"], g)
    s2 = apply(s1, tr["t2_assume"], g)
    print("t1 enabled in S0:", enabled(tr["t1_login"], s, g))
    print("t5_logout enabled after t2 (invariant check):", enabled(tr["t5_logout"], s2, g))
    print("trace t1,t2,t3 valid:", end(s, [tr["t1_login"], tr["t2_assume"], tr["t3_read"]], g) is not None)
    print("t3_read independent of b1_backup in s2:", independent(tr["t3_read"], tr["b1_backup"], s2, g))
    print("t2_assume independent of t5_logout in s1:",
          independent(tr["t2_assume"], tr["t5_logout"], s1, g))

    print("\n== Compromise over the family F_b(D) = {M1, M2} ==")
    for m in ("M1", "M2"):
        path = reachable(FAMILY[m], S0[m], GOAL)
        print(f"{m}: compromised={path is not None} witness={path}")
    for b in [(), ("k1",), ("k3",), ("k1", "k3")]:
        per = {m: compromised(b, m) for m in ("M1", "M2")}
        print(f"bundle {set(b) or '{}'}: possibly={any(per.values())} necessarily={all(per.values())}")

    print("\n== Every bundle (cost, safe in M1, safe in M2, utility M1, utility M2) ==")
    for r in range(len(CONTROLS) + 1):
        for b in combinations(sorted(CONTROLS), r):
            print(f"{'{' + ','.join(b) + '}':<14} J={cost(b)}  "
                  f"safe=({not compromised(b,'M1')},{not compromised(b,'M2')})  "
                  f"U=({utility(b,'M1'):.1f},{utility(b,'M2'):.1f})")

    print("\n== Synthesis results ==")
    print("robust, eta=1.0:", synthesize(["M1", "M2"], 1.0))
    print("robust, eta=0.5:", synthesize(["M1", "M2"], 0.5))
    print("attack-only (eta=0):", synthesize(["M1", "M2"], 0.0))
    print("M1 only, eta=1.0:", synthesize(["M1"], 1.0))
    b = synthesize(["M1"], 1.0)[1]
    print("  M1-only choice compromised in M2:", compromised(b, "M2"))

    print("\n== Excess authority with subsumption ==")
    H = {("read", "/data/*"), ("send", "*@corp"), ("delete", "/tmp/*"), ("share", "/data/report")}
    w = {("read", "/data/*"): 3, ("send", "*@corp"): 2, ("delete", "/tmp/*"): 4, ("share", "/data/report"): 1}
    R1 = {("read", "/data/report"), ("send", "boss@corp")}
    R2 = {("read", "/data/report"), ("share", "/data/report")}
    print("plain subset R1<=H:", R1 <= H, " covered:", req_feasible(H, R1))
    print("plain subset R2<=H:", R2 <= H, " covered:", req_feasible(H, R2))
    ex = [excess(H, R, w) for R in (R1, R2) if req_feasible(H, R)]
    print("excess per realization:", ex, " EA_min =", min(ex), " EA_max =", max(ex))

if __name__ == "__main__":
    main()
