# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
"""MkDocs hook: generate the API reference from the Go source, and point the
pages that show repository files at the right places on the site.

Each public package becomes one page under api/, built from `go doc -all` each
time the documentation is built, so the reference cannot drift from the code.
A page shows the package overview and every exported declaration exactly as
`go doc` prints it, with its doc comment. api/index.md lists the packages and
every exported identifier A-Z.

Go must be on PATH: without it the build fails rather than publishing an empty
reference.
"""
import html
import re
import shutil
import subprocess
from pathlib import Path

from mkdocs.exceptions import PluginError
from mkdocs.plugins import event_priority
from mkdocs.structure.files import File

MODULE = "github.com/shieldled/goshieldnet"
PKG_GO_DEV = "https://pkg.go.dev/" + MODULE

# The public packages, in the order the reference presents them:
# (directory, page name, one-line role).
PACKAGES = [
    ("sledclient", "sledclient", "The client: connect to a device and run its commands."),
    ("discovery", "discovery", "Find devices on the local network over mDNS."),
    ("sled", "sled", "The ShieldLED application payloads, both directions."),
    ("v1", "v1", "The ShieldNet v1 transport and message layer, both roles."),
    ("sledclient/sledclienttest", "sledclienttest", "An in-process device for tests."),
]

SECTIONS = {"CONSTANTS", "VARIABLES", "FUNCTIONS", "TYPES"}
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def _go_doc(root, pkg):
    go = shutil.which("go")
    if go is None:
        raise PluginError(
            "docs/hooks/api_reference.py: the API reference is generated with "
            "`go doc`, and no `go` command is on PATH. Install Go (the version "
            "in go.mod) and build again.")
    res = subprocess.run([go, "doc", "-all", "./" + pkg], cwd=root,
                         capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        raise PluginError(f"docs/hooks/api_reference.py: `go doc -all ./{pkg}` "
                          f"failed (exit {res.returncode}): {res.stderr.strip()}")
    return res.stdout


def parse(text):
    """`go doc -all` output -> (overview lines, [(section, code lines, doc lines)])."""
    lines = text.splitlines()
    assert lines and lines[0].startswith("package "), lines[:1]
    i, overview = 1, []
    while i < len(lines) and lines[i] not in SECTIONS:
        overview.append(lines[i])
        i += 1
    items, section, cur, open_block = [], None, None, False
    for line in lines[i:]:
        if open_block:                       # inside a { } or ( ) declaration body
            cur[1].append(line)
            open_block = not (line.startswith("}") or line.startswith(")"))
        elif line in SECTIONS:
            section, cur = line, None
        elif line.startswith("    "):        # doc comment, indented by four spaces
            cur[2].append(line[4:])
        elif line == "":
            if cur is not None:
                cur[2].append("")
        else:                                # a new declaration at column 0
            cur = (section, [line], [])
            items.append(cur)
            open_block = line.endswith("{") or line.endswith("(")
    return _trim(overview), [(s, c, _trim(d)) for s, c, d in items]


def _trim(lines):
    lines = list(lines)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def _names(code):
    """-> [(name, kind, receiver)] declared by one item's code."""
    head = code[0]
    m = re.match(rf"func \((?:{IDENT} )?\*?({IDENT})(?:\[[^\]]*\])?\) ({IDENT})", head)
    if m:
        return [(m.group(2), "method", m.group(1))]
    m = re.match(rf"func ({IDENT})", head)
    if m:
        return [(m.group(1), "func", None)]
    m = re.match(rf"type ({IDENT})", head)
    if m:
        return [(m.group(1), "type", None)]
    m = re.match(r"(const|var) ", head)
    if not m:
        return []
    kind = m.group(1)
    if head.rstrip().endswith("("):          # a grouped block: one name per line
        out = []
        for l in code[1:]:
            n = re.match(rf"\t({IDENT}(?:\s*,\s*{IDENT})*)", l)
            if n and not l.lstrip().startswith("//"):
                out += [(x.strip(), kind, None) for x in n.group(1).split(",")]
        return out
    n = re.match(rf"(?:const|var) ({IDENT}(?:\s*,\s*{IDENT})*)", head)
    return [(x.strip(), kind, None) for x in n.group(1).split(",")] if n else []


def _esc(s):
    s = html.escape(s, quote=False)
    s = re.sub(r"([\\`*_\[\]{}#!|])", r"\\\1", s)
    return s


LIST_RE = re.compile(r"( *)([-*+•]|\d+[.)]) (.*)")


def _md_text(lines):
    """Go doc comment text, as `go doc` prints it, -> Markdown."""
    out, i, n = [], 0, len(lines)
    in_list = False
    while i < n:
        l = lines[i]
        if l.startswith("\t"):                    # a code block
            block = []
            while i < n and (lines[i].startswith("\t") or (
                    not lines[i].strip() and i + 1 < n and lines[i + 1].startswith("\t"))):
                block.append(lines[i][1:])
                i += 1
            out += ["", "```text", *block, "```", ""]
            in_list = False
            continue
        m = LIST_RE.match(l)
        if m and len(m.group(1)) >= 2:            # a list item, continued further in
            depth, text = len(m.group(1)), [m.group(3)]
            i += 1
            while i < n and lines[i].startswith(" " * (depth + 2)) and not LIST_RE.match(lines[i]):
                text.append(lines[i].strip())
                i += 1
            if not in_list:
                out.append("")
            out.append(("1." if m.group(2)[0].isdigit() else "-") + " " + _esc(" ".join(text)))
            in_list = True
            continue
        if not l.strip():
            out.append("")
        elif l.startswith("# "):                   # a doc-comment heading
            out += ["", "**" + _esc(l[2:]) + "**", ""]
        else:
            if in_list:
                out.append("")
            t = _esc(l.strip())
            out.append("\\" + t if re.match(r"([-+]|\d+\.)( |$)", t) else t)
        in_list = False
        i += 1
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def _anchor(name, kind, recv):
    return (f"{recv}.{name}" if recv else name).replace(".", "-").lower() \
        if kind != "type" else f"type-{name.lower()}"


def _summary(doc):
    text = " ".join(l.strip() for l in doc if l.strip())
    m = re.match(r"(.+?\.)(\s|$)", text)
    return (m.group(1) if m else text)


def _own_comment(code, name):
    """The comment on one name inside a grouped const or var block: the comment
    at the end of its line, else the comment lines directly above it."""
    if len(code) < 2:
        return []
    for k, l in enumerate(code[1:], 1):
        if re.match(rf"\t(?:{IDENT}\s*,\s*)*{re.escape(name)}\b", l):
            if "//" in l:
                return [l.split("//", 1)[1].strip()]
            above = []
            while k > 1 and code[k - 1].lstrip().startswith("//"):
                k -= 1
                above.insert(0, code[k].lstrip()[2:].strip())
            return above
    return []


def render(pkg, page, role, text):
    """-> (markdown, [(name, kind, recv, anchor, summary)], package synopsis)."""
    overview, items = parse(text)
    path = f"{MODULE}/{pkg}"
    md = [f"# Package {page}", "",
          f"`import \"{path}\"`: {role} "
          f"Also on [pkg.go.dev]({PKG_GO_DEV}/{pkg}).", "",
          "<!-- Generated from `go doc -all` by docs/hooks/api_reference.py; "
          "edit the Go doc comments, not this page. -->", "",
          "## Overview", "", _md_text(overview), ""]
    symbols, seen = [], set()
    section = None
    for sec, code, doc in items:
        if sec != section:
            section = sec
            md += [f"## {sec.capitalize()}", ""]
        names = _names(code)
        anchors = []
        for name, kind, recv in names:
            a = _anchor(name, kind, recv)
            while a in seen:
                a += "-"
            seen.add(a)
            anchors.append(a)
            symbols.append((name, kind, recv, a, _summary(_own_comment(code, name)) or _summary(doc)))
        if names:
            name, kind, recv = names[0]
            title = {"method": f"func ({recv}) {name}", "func": f"func {name}",
                     "type": f"type {name}"}.get(kind, f"{kind} " + ", ".join(n[0] for n in names))
            level = "####" if kind == "method" or (kind == "func" and sec == "TYPES") else "###"
            md += [f"{level} {_esc(title)} {{#{anchors[0]}}}", ""]
            md += [f'<a id="{a}"></a>' for a in anchors[1:]]
            if anchors[1:]:
                md.append("")
        md += ["```go", *code, "```", ""]
        if doc:
            md += [_md_text(doc), ""]
    return "\n".join(md), symbols, _summary(overview)


def build(root):
    """-> {docs path: markdown}, nav entries, [(page, plain summary)]."""
    pages, nav, descs, everything, rows = {}, ["api/index.md"], [], [], []
    for pkg, page, role in PACKAGES:
        if not (root / pkg).is_dir():
            raise PluginError(f"docs/hooks/api_reference.py: package directory {pkg}/ is missing")
        md, syms, synopsis = render(pkg, page, role, _go_doc(root, pkg))
        doc_page = f"api/{page}.md"
        pages[doc_page] = md
        nav.append(doc_page)
        descs.append((doc_page, synopsis))
        rows.append(f"| [`{pkg}`]({page}.md) | {_esc(role)} | {_esc(synopsis)} | "
                    f"[pkg.go.dev]({PKG_GO_DEV}/{pkg}) |")
        everything += [(s, page) for s in syms]

    idx = ["# API reference", "",
           "Generated from the Go source with `go doc -all` each time the documentation "
           "is built. Each page shows a package's overview and every exported "
           "declaration exactly as `go doc` prints it, with its doc comment. The same "
           f"reference is on [pkg.go.dev]({PKG_GO_DEV}). The "
           "[README](../index.md) explains how the packages fit together; the "
           "[examples](../examples/README.md) show them in use.", "",
           "## Packages", "",
           "Most applications need only `sledclient` (with `discovery` to find devices). "
           "`v1` is the transport underneath, and a device built in Go uses it directly.", "",
           "| Package | Role | Summary | |", "| --- | --- | --- | --- |", *rows, "",
           "## All exported identifiers", "",
           "| Identifier | Kind | Package | Description |", "| --- | --- | --- | --- |"]
    for (name, kind, recv, anchor, summ), page in sorted(
            everything, key=lambda e: ((e[0][2] + "." if e[0][2] else "") + e[0][0]).lower()):
        label = f"{recv}.{name}" if recv else name
        idx.append(f"| [`{label}`]({page}.md#{anchor}) | {kind} | `{page}` | {_esc(summ)} |")
    pages["api/index.md"] = "\n".join(idx) + "\n"
    return pages, nav, descs


_PAGES = {}


def on_config(config):
    root = Path(config["config_file_path"]).parent
    pages, nav, descs = build(root)
    _PAGES.clear()
    _PAGES.update(pages)
    for i, entry in enumerate(config["nav"] or []):
        if isinstance(entry, dict) and "API reference" in entry:
            config["nav"][i] = {"API reference": nav}
    # llms.txt: list each package page with its summary. A glob entry would give
    # them none.
    llmstxt = config["plugins"].get("llmstxt")
    if llmstxt is not None:
        for inputs in llmstxt.config.sections.values():
            if "api/*.md" in inputs:
                at = inputs.index("api/*.md")
                inputs[at:at + 1] = [{page: desc} for page, desc in descs]
    return config


# Before every plugin, so llmstxt sees the generated pages.
@event_priority(100)
def on_files(files, config):
    for path, content in _PAGES.items():
        files.append(File.generated(config, path, content=content))
    return files


# The examples page shows examples/README.md followed by each example's source
# (docs/examples/README.md). The README links to the example directories, which
# works on GitHub; on the site those links go to the source sections instead.
EXAMPLE_SOURCES = {"server": "server-main-go", "client": "client-main-go"}

# Pages that show a file from the repository root (README.md, AGENTS.md,
# CHANGELOG.md). Their links into docs/ are written for GitHub; on the site,
# docs/ is the root.
ROOT_PAGES = {"index.md", "agents.md", "changelog.md"}


def on_page_markdown(markdown, page, config, files):
    uri = page.file.src_uri
    if uri == "examples/README.md":
        for name, anchor in EXAMPLE_SOURCES.items():
            markdown = markdown.replace(f"]({name})", f"](#{anchor})")
    elif uri in ROOT_PAGES:
        markdown = markdown.replace("](docs/", "](")
    return markdown
