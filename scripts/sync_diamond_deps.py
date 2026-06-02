#!/usr/bin/env python3
"""
sync_diamond_deps.py — resolve a Zig "diamond dependency" by converging the
conflicting package onto a single version across the local DevNW sibling
ecosystem, patch-tagging each consumer in topological order.

This is the companion fix-tool to `detect_diamond_deps.py` (which only
*reports* diamonds). It has two modes:

LOCAL mode (default — safe for pre-commit):
    Detect diamonds in THIS repo. For each conflicting package P, pick the
    target = highest version among the candidates. Then, for each DIRECT dep D
    of this repo whose subtree still pins a non-target P, look for a released
    sibling version of D that already converges on P=target and repoint THIS
    repo's `build.zig.zon` to it. No other repo is mutated; nothing is pushed.
    If a needed converged version of D does not exist yet, the tool fails with
    a clear "upstream not ready — run --cascade" message (exit 1). This is the
    mode the pre-commit hook invokes when `detect-diamond-deps` fires.

CASCADE mode (`--cascade`, maintainer-only):
    Propagate a leaf bump (e.g. a new `tls` release) through the WHOLE local
    sibling ecosystem. Topologically orders every transitive consumer of the
    conflicting package, and for each: checks it out at the base commit the
    --base-from root currently pins (minimal drift), bumps its pins for any
    already-bumped dep to that dep's new tag, refreshes its cache, verifies the
    diamond is gone, commits, creates the lowest-increment patch tag, and
    (with --apply) pushes branch+tag. Finally rewrites the root repo's pins.
    Without --apply it is a DRY RUN that prints the full plan.

Usage
-----
    # pre-commit / local (default): resolve THIS repo's pins, no pushes
    scripts/sync_diamond_deps.py

    # maintainer: plan the ecosystem cascade for a known leaf bump (dry run)
    scripts/sync_diamond_deps.py --cascade \
        --target tls=v0.1.9#0cbbf1a4f0389c46ddde6947979c62d7afbcf076 \
        --base-from .

    # maintainer: actually execute it (pushes to every sibling repo)
    scripts/sync_diamond_deps.py --cascade --apply \
        --target tls=v0.1.9#0cbbf1a4f0389c46ddde6947979c62d7afbcf076 \
        --base-from .

Sibling repos are discovered under the colon-separated $DEVNW_SIBLING_BASES
(default: ~/src/devnw/zig:~/src/devnw/codepros/geode) plus the parent of the
current repo. Each repo is matched by the `.name` in its `build.zig.zon`.

Exit codes: 0 success / clean, 1 unresolved or error, 2 tooling failure.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Reuse the parser + walker from the sibling detector.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect_diamond_deps as ddd  # noqa: E402

SEMVER_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
NAME_RE = re.compile(r"\.name\s*=\s*(?:\.([A-Za-z_][A-Za-z0-9_]*)|\"([^\"]+)\")")
DEVNW_URL_RE = re.compile(
    r"gitlab\.com/devnw/(?:zig|codepros/geode)/([A-Za-z0-9_.-]+?)\.git"
)


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def run(
    cmd: list[str], cwd: Path | None = None, check: bool = True, capture: bool = True
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=capture,
    )


# ---------------------------------------------------------------------------
# zon helpers
# ---------------------------------------------------------------------------
def zon_name(zon_text: str) -> str | None:
    m = NAME_RE.search(zon_text)
    if not m:
        return None
    return m.group(1) or m.group(2)


def zon_direct_deps(zon_path: Path) -> list[tuple[str, str, str | None]]:
    """(dep_field_name, hash, url) for each direct dep of the zon."""
    text = zon_path.read_text(encoding="utf-8", errors="replace")
    block = ddd._find_dependencies_block(text)
    if block is None:
        return []
    return ddd._parse_dep_entries(block)


def devnw_name_from_url(url: str | None) -> str | None:
    if not url:
        return None
    m = DEVNW_URL_RE.search(url)
    if not m:
        return None
    # geode-client-zig.git -> dep field is geode_client_zig; normalize on the
    # repo (URL) name, callers map field<->repo separately.
    return m.group(1)


# ---------------------------------------------------------------------------
# sibling discovery
# ---------------------------------------------------------------------------
@dataclass
class Repo:
    field_name: str  # zon dependency field name (e.g. geode_client_zig)
    repo_name: str  # URL/repo slug (e.g. geode-client-zig)
    path: Path  # local checkout
    url: str  # canonical git+https url (no #ref)


def discover_repos(extra_root: Path) -> dict[str, Repo]:
    """Map zon-field-name -> Repo for every local DevNW sibling checkout."""
    bases_env = os.environ.get(
        "DEVNW_SIBLING_BASES",
        f"{Path.home()}/src/devnw/zig:{Path.home()}/src/devnw/codepros/geode",
    )
    bases = [Path(b).expanduser() for b in bases_env.split(":") if b]
    bases.append(extra_root.parent)
    repos: dict[str, Repo] = {}
    for base in bases:
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            zon = child / "build.zig.zon"
            if not (child / ".git").exists() or not zon.exists():
                continue
            try:
                name = zon_name(zon.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if not name:
                continue
            repo_slug = child.name  # directory name == repo slug
            url = _url_for(child)
            if name not in repos:
                repos[name] = Repo(
                    field_name=name, repo_name=repo_slug, path=child.resolve(), url=url
                )
    return repos


def _url_for(repo_path: Path) -> str:
    try:
        out = run(["git", "remote", "get-url", "origin"], cwd=repo_path).stdout.strip()
    except subprocess.CalledProcessError:
        return ""
    # git@gitlab.com:devnw/zig/tls.git -> git+https://gitlab.com/devnw/zig/tls.git
    m = re.search(
        r"[:/](devnw/(?:zig|codepros/geode)/[A-Za-z0-9_.-]+?)(?:\.git)?$", out
    )
    if not m:
        return ""
    return f"git+https://gitlab.com/{m.group(1)}.git"


# ---------------------------------------------------------------------------
# git / tag helpers
# ---------------------------------------------------------------------------
def latest_patch_tag(repo: Repo) -> tuple[int, int, int]:
    out = run(["git", "tag", "--list", "v*"], cwd=repo.path, check=False).stdout
    best = (0, 0, 0)
    for line in out.splitlines():
        m = SEMVER_TAG_RE.match(line.strip())
        if m:
            t = tuple(int(x) for x in m.groups())
            if t > best:
                best = t  # type: ignore[assignment]
    return best  # type: ignore[return-value]


def remote_tag_exists(repo: Repo, tag: str) -> bool:
    out = run(
        ["git", "ls-remote", "origin", f"refs/tags/{tag}"], cwd=repo.path, check=False
    ).stdout
    return bool(out.strip())


def next_free_patch_tag(repo: Repo) -> str:
    """Lowest-increment patch tag not already used locally or on the remote."""
    major, minor, patch = latest_patch_tag(repo)
    while True:
        patch += 1
        tag = f"v{major}.{minor}.{patch}"
        local = run(
            ["git", "tag", "--list", tag], cwd=repo.path, check=False
        ).stdout.strip()
        if not local and not remote_tag_exists(repo, tag):
            return tag


def pinned_commit(root_zon_text: str, field_name: str) -> str | None:
    block = ddd._find_dependencies_block(root_zon_text)
    if not block:
        return None
    for name, _h, url in ddd._parse_dep_entries(block):
        if name == field_name and url and "#" in url:
            return url.split("#", 1)[1]
    return None


def zig_pkg_hash(consumer_path: Path, url_with_ref: str) -> str | None:
    """`zig fetch <url>` from inside consumer_path; returns the package hash."""
    try:
        cp = run(["zig", "fetch", url_with_ref], cwd=consumer_path, check=True)
    except subprocess.CalledProcessError as e:
        log(f"    zig fetch failed: {e.stderr.strip()[:200]}")
        return None
    out = cp.stdout.strip().splitlines()
    return out[-1].strip() if out else None


def rewrite_pin(
    zon_text: str, field_name: str, new_url: str, new_hash: str
) -> tuple[str, int]:
    """Replace the .url and .hash of `.<field_name> = .{ ... }`.

    Robust to comment-heavy blocks (a single spanning regex breaks when a
    comment between `.{` and `.url` contains a brace): locate the dep marker,
    bound the block by the next dep marker, then replace the first .url/.hash
    inside it.
    """
    marker = re.search(r"\." + re.escape(field_name) + r"\s*=\s*\.\{", zon_text)
    if not marker:
        return zon_text, 0
    start = marker.end()
    nxt = re.search(r"\n\s*\.[A-Za-z_][A-Za-z0-9_]*\s*=\s*\.\{", zon_text[start:])
    end = start + nxt.start() if nxt else len(zon_text)
    block = zon_text[start:end]
    block, nu = re.subn(
        r'(\.url\s*=\s*")[^"]+(")',
        lambda m: m.group(1) + new_url + m.group(2),
        block,
        count=1,
    )
    block, nh = re.subn(
        r'(\.hash\s*=\s*")[^"]+(")',
        lambda m: m.group(1) + new_hash + m.group(2),
        block,
        count=1,
    )
    if nu == 0 or nh == 0:
        return zon_text, 0
    return zon_text[:start] + block + zon_text[end:], 1


def refresh_cache(repo_path: Path) -> bool:
    for d in ("zig-pkg", ".zig-cache"):
        p = repo_path / d
        if p.exists():
            run(["rm", "-rf", str(p)], check=False)
    cp = run(["zig", "build", "--fetch"], cwd=repo_path, check=False)
    return cp.returncode == 0


def diamond_clean(repo_path: Path) -> bool:
    cp = run(
        [
            sys.executable,
            str(Path(__file__).resolve().parent / "detect_diamond_deps.py"),
            str(repo_path),
        ],
        check=False,
    )
    return cp.returncode == 0


# ---------------------------------------------------------------------------
# ecosystem graph + topo sort
# ---------------------------------------------------------------------------
def ecosystem_edges(repos: dict[str, Repo]) -> dict[str, set[str]]:
    """field_name -> set of devnw dep field_names it directly pins."""
    edges: dict[str, set[str]] = {}
    for name, repo in repos.items():
        deps = set()
        for dep_field, _h, _u in zon_direct_deps(repo.path / "build.zig.zon"):
            if dep_field in repos:
                deps.add(dep_field)
        edges[name] = deps
    return edges


def consumers_of(target: str, edges: dict[str, set[str]]) -> set[str]:
    """All field_names that transitively depend on `target` (excluding target)."""
    rev: dict[str, set[str]] = {n: set() for n in edges}
    for n, deps in edges.items():
        for d in deps:
            rev.setdefault(d, set()).add(n)
    out: set[str] = set()
    stack = [target]
    while stack:
        cur = stack.pop()
        for parent in rev.get(cur, ()):
            if parent not in out:
                out.add(parent)
                stack.append(parent)
    return out


def topo_order(subset: set[str], edges: dict[str, set[str]]) -> list[str]:
    order: list[str] = []
    temp: set[str] = set()
    done: set[str] = set()

    def visit(n: str) -> None:
        if n in done:
            return
        if n in temp:
            raise RuntimeError(f"dependency cycle at {n}")
        temp.add(n)
        for d in sorted(edges.get(n, ())):
            if d in subset:
                visit(d)
        temp.discard(n)
        done.add(n)
        order.append(n)

    for n in sorted(subset):
        visit(n)
    return order


# ---------------------------------------------------------------------------
# cascade
# ---------------------------------------------------------------------------
@dataclass
class Bumped:
    field_name: str
    tag: str
    commit: str
    pkg_hash: str
    url_with_ref: str


def parse_target(spec: str) -> tuple[str, str, str]:
    # tls=v0.1.9#<commit>
    name, rest = spec.split("=", 1)
    ref, commit = rest.split("#", 1)
    return name, ref, commit


def cascade(root_repo: Path, target_spec: str, base_from: Path, apply: bool) -> int:
    repos = discover_repos(root_repo)
    tname, tref, tcommit = parse_target(target_spec)
    if tname not in repos:
        log(f"sync-diamond: target '{tname}' has no local sibling checkout")
        return 2
    target_repo = repos[tname]

    # The target's package hash (it must already be pushed at tref/tcommit).
    target_url = f"{target_repo.url}?ref={tref}#{tcommit}"
    thash = zig_pkg_hash(root_repo, target_url)
    if not thash:
        log(
            f"sync-diamond: cannot fetch target {tname} at {tref}#{tcommit[:8]} (is it pushed?)"
        )
        return 2

    edges = ecosystem_edges(repos)
    subset = consumers_of(tname, edges)
    # Only bump consumers that the base-from root ACTUALLY pulls — restrict to
    # the packages present in its resolved transitive graph (not every sibling
    # checkout on disk).
    cache_env = os.environ.get("ZIG_GLOBAL_CACHE_DIR")
    cache_root = Path(cache_env) if cache_env else Path.home() / ".cache" / "zig"
    active = set(ddd.collect_transitive(base_from / "build.zig.zon", cache_root).keys())
    active.add(tname)
    subset &= active
    order = topo_order(subset, edges)

    bumped: dict[str, Bumped] = {
        tname: Bumped(tname, tref, tcommit, thash, target_url),
    }

    log("=" * 72)
    log(f"DIAMOND CASCADE  target={tname} -> {tref}#{tcommit[:8]} ({thash})")
    log(f"mode={'APPLY (will push to remotes)' if apply else 'DRY RUN'}")
    log(f"consumers to bump ({len(order)}): {', '.join(order)}")
    log("=" * 72)

    base_zon = (base_from / "build.zig.zon").read_text()

    for field in order:
        repo = repos[field]
        log(f"\n--- {field}  ({repo.repo_name}) ---")

        # Determine this repo's minimal base = the commit the root currently pins.
        base_commit = pinned_commit(base_zon, field)
        if not base_commit:
            log(
                f"  {field}: not directly pinned by base-from root; using origin/main HEAD"
            )

        # Which of this repo's direct deps were bumped (need re-pin here)?
        deps_here = {n for (n, _h, _u) in zon_direct_deps(repo.path / "build.zig.zon")}
        to_repin = [d for d in deps_here if d in bumped]
        log(f"  re-pin deps: {', '.join(to_repin) if to_repin else '(none)'}")
        new_tag = next_free_patch_tag(repo)
        log(f"  new tag: {new_tag}")

        if not apply:
            for d in to_repin:
                b = bumped[d]
                log(f"    {d} -> {b.tag}#{b.commit[:8]} ({b.pkg_hash})")
            # We cannot compute this repo's own hash until it's pushed; defer.
            bumped[field] = Bumped(
                field,
                new_tag,
                "<dry-run>",
                "<dry-run>",
                f"{repo.url}?ref={new_tag}#<dry-run>",
            )
            continue

        # APPLY: checkout the minimal base on a working branch.
        branch = "gap-diamond-sync"
        if base_commit:
            run(["git", "fetch", "origin", base_commit], cwd=repo.path, check=False)
            run(["git", "checkout", "-B", branch, base_commit], cwd=repo.path)
        else:
            run(["git", "checkout", "-B", branch, "origin/main"], cwd=repo.path)

        # Rewrite each bumped dep's pin.
        zon_path = repo.path / "build.zig.zon"
        text = zon_path.read_text()
        for d in to_repin:
            b = bumped[d]
            new_text, n = rewrite_pin(text, d, b.url_with_ref, b.pkg_hash)
            if n == 0:
                log(f"  ERROR: could not rewrite pin for {d} in {field}")
                return 1
            text = new_text
        zon_path.write_text(text)

        if not refresh_cache(repo.path):
            log(f"  ERROR: `zig build --fetch` failed for {field}")
            return 1
        if not diamond_clean(repo.path):
            log(
                f"  ERROR: {field} still has a diamond after re-pin (an indirect consumer was missed)"
            )
            return 1

        run(["git", "add", "build.zig.zon"], cwd=repo.path)
        run(
            [
                "git",
                "commit",
                "-m",
                f"chore(deps): converge {tname} onto {tref} (GAP-0838 diamond sync)",
            ],
            cwd=repo.path,
        )
        new_commit = run(["git", "rev-parse", "HEAD"], cwd=repo.path).stdout.strip()
        run(
            [
                "git",
                "tag",
                "-a",
                new_tag,
                "-m",
                f"{new_tag} — converge {tname} {tref} (GAP-0838 diamond sync)",
            ],
            cwd=repo.path,
        )
        run(["git", "push", "origin", branch], cwd=repo.path)
        run(["git", "push", "origin", new_tag], cwd=repo.path)

        url_ref = f"{repo.url}?ref={new_tag}#{new_commit}"
        h = zig_pkg_hash(root_repo, url_ref)
        if not h:
            log(f"  ERROR: could not compute pkg hash for {field}@{new_tag}")
            return 1
        bumped[field] = Bumped(field, new_tag, new_commit, h, url_ref)
        log(f"  pushed {field} {new_tag} ({new_commit[:8]}) hash={h}")

    # Finally rewrite the root repo's own pins.
    log("\n--- root repo re-pin ---")
    root_zon = root_repo / "build.zig.zon"
    text = root_zon.read_text()
    root_deps = {n for (n, _h, _u) in zon_direct_deps(root_zon)}
    for d in sorted(root_deps & set(bumped)):
        b = bumped[d]
        if apply and b.commit == "<dry-run>":
            continue
        log(f"  {d} -> {b.tag}#{str(b.commit)[:8]} ({b.pkg_hash})")
        if apply:
            new_text, n = rewrite_pin(text, d, b.url_with_ref, b.pkg_hash)
            if n == 0:
                log(
                    f"  ERROR: could not rewrite root pin for {d} — fix build.zig.zon "
                    f"by hand: {d} -> {b.url_with_ref} / {b.pkg_hash}"
                )
                return 1
            text = new_text
    if apply:
        root_zon.write_text(text)
        log(
            "  root build.zig.zon updated; run `zig build --fetch && make build` to verify."
        )
    else:
        log("\nDRY RUN complete — re-run with --apply to execute the cascade.")
    return 0


# ---------------------------------------------------------------------------
# local (pre-commit) mode
# ---------------------------------------------------------------------------
def local_resolve(root_repo: Path, apply: bool) -> int:
    cache_env = os.environ.get("ZIG_GLOBAL_CACHE_DIR")
    cache_root = Path(cache_env) if cache_env else Path.home() / ".cache" / "zig"
    graph = ddd.collect_transitive(root_repo / "build.zig.zon", cache_root)
    diamonds = ddd.find_diamonds(graph)
    if not diamonds:
        log("sync-diamond: no diamonds — nothing to do.")
        return 0
    log("sync-diamond: diamond(s) detected:")
    for name, pinned in diamonds:
        versions = sorted({(u or h) for (h, u) in pinned})
        log(f"  {name}: {len(pinned)} hashes -> {versions}")
    log("")
    log(
        "This repo cannot resolve a transitive diamond on its own — the "
        "intermediate libraries must be re-released so a single version "
        "propagates. Run the ecosystem cascade (maintainer):"
    )
    log("")
    for name, _pinned in diamonds:
        log("  scripts/sync_diamond_deps.py --cascade --apply \\")
        log(f"      --target {name}=<highest-version#commit> --base-from .")
    log("")
    log(
        "(highest published version of the conflicting package wins; tls example: --target tls=v0.1.9#<commit>)"
    )
    return 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Resolve Zig diamond deps by converging versions."
    )
    ap.add_argument(
        "--cascade",
        action="store_true",
        help="maintainer mode: bump every transitive consumer across siblings",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="execute (commit/tag/push); without it, dry run",
    )
    ap.add_argument("--target", help="conflicting pkg bump, e.g. tls=v0.1.9#<commit>")
    ap.add_argument(
        "--base-from",
        default=".",
        help="repo whose current pins define each sibling's minimal base",
    )
    ap.add_argument("--repo", default=".", help="repo to operate on / root for cascade")
    args = ap.parse_args(argv[1:])

    root = Path(args.repo).resolve()
    if not (root / "build.zig.zon").exists():
        log(f"sync-diamond: no build.zig.zon at {root}")
        return 2

    if args.cascade:
        if not args.target:
            log("sync-diamond: --cascade requires --target <pkg>=<vX.Y.Z>#<commit>")
            return 2
        return cascade(root, args.target, Path(args.base_from).resolve(), args.apply)
    return local_resolve(root, args.apply)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
