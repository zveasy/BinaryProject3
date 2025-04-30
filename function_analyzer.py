#!/usr/bin/env python3
"""
Disassemble the `main` function of a PE/ELF binary with angr, dumping a
JSON report whose addresses are in 0x-prefixed hexadecimal notation.
"""

import json
from typing import Dict, List, Set, Any

import angr


# ────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ────────────────────────────────────────────────────────────────────────────
def hexify(n: int) -> str:
    """Return a 64-bit address as a zero-padded hex string, e.g. 0x0000000140001745."""
    return f"0x{n:016x}"


# ────────────────────────────────────────────────────────────────────────────
# Symbol / CFG helpers (Zak’s part)
# ────────────────────────────────────────────────────────────────────────────
def get_main_function_addr(project: angr.Project) -> int:
    """
    Locate the address of the `main` function.
    Prefer the symbol table; fall back to CFGFast discovery.
    """
    for sym in project.loader.main_object.symbols:
        if getattr(sym, "is_function", False) and sym.name == "main":
            return int(sym.rebased_addr)

    cfg = project.analyses.CFGFast(normalize=True)
    for func in cfg.kb.functions.values():
        if func.name == "main":
            return int(func.addr)

    raise ValueError("Could not find 'main' function.")


def get_direct_successors(block) -> List[int]:
    """Return *static* jump/call successors of a basic block."""
    return block.vex.constant_jump_targets


# ────────────────────────────────────────────────────────────────────────────
# CFG traversal & data collection (Aaron’s part)
# ────────────────────────────────────────────────────────────────────────────
def recursive_descent(
    project: angr.Project,
    addr: int,
    visited: Set[int],
    edges: List[tuple],
    block_info: Dict[int, List[Dict[str, Any]]],
    jump_call_ret_counts: Dict[str, int],
    path: List[int],
    back_edges: Set[tuple],
    max_depth: int = 100,
    depth: int = 0,
) -> None:
    """Depth-first walk of a single function’s CFG."""
    if depth > max_depth or addr in visited:
        # loop (back-edge) detection
        if addr in path:
            prev = path[-1] if path else None
            if prev is not None:
                back_edges.add((prev, addr))
        return

    visited.add(addr)
    path.append(addr)

    try:
        block = project.factory.block(addr)
    except Exception:
        path.pop()
        return

    # Disassemble instructions with Capstone
    insns: List[Dict[str, Any]] = []
    for insn in getattr(block.capstone, "insns", []):
        insns.append(
            {
                "address": hexify(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            }
        )
        if insn.mnemonic.startswith("j"):
            jump_call_ret_counts["jumps"] += 1
        elif insn.mnemonic.startswith("call"):
            jump_call_ret_counts["calls"] += 1
        elif insn.mnemonic.startswith("ret"):
            jump_call_ret_counts["returns"] += 1

    block_info[addr] = insns

    # Recurse on direct successors
    for succ in get_direct_successors(block):
        edges.append((addr, succ))
        recursive_descent(
            project,
            succ,
            visited,
            edges,
            block_info,
            jump_call_ret_counts,
            path,
            back_edges,
            max_depth,
            depth + 1,
        )

    # Detect back-edges already on path
    for succ in get_direct_successors(block):
        if succ in path:
            back_edges.add((addr, succ))

    path.pop()


def analyze_main_recursive(project: angr.Project, func_addr: int) -> Dict[str, Any]:
    """Return a structured JSON-ready dict describing the `main` function."""
    visited: Set[int] = set()
    edges: List[tuple] = []
    block_info: Dict[int, List[Dict[str, Any]]] = {}
    back_edges: Set[tuple] = set()
    jump_call_ret_counts = {"jumps": 0, "calls": 0, "returns": 0}

    recursive_descent(
        project,
        func_addr,
        visited,
        edges,
        block_info,
        jump_call_ret_counts,
        [],
        back_edges,
    )

    return {
        "name": "main",
        "address": hexify(func_addr),
        "blocks": [
            {
                "block_address": hexify(addr),
                "instructions": block_info[addr],
            }
            for addr in sorted(block_info.keys())
        ],
        "instruction_counts": {
            "jumps": jump_call_ret_counts["jumps"],
            "calls": jump_call_ret_counts["calls"],
            "returns": jump_call_ret_counts["returns"],
            "total_blocks": len(block_info),
            "total_instructions": sum(len(insns) for insns in block_info.values()),
        },
        "loops": [{"src": hexify(src), "dst": hexify(dst)} for (src, dst) in back_edges],
    }


# ────────────────────────────────────────────────────────────────────────────
# Script entry point
# ────────────────────────────────────────────────────────────────────────────
def main() -> None:
    binary_path = "helloworld.exe"  # ← update as needed
    project = angr.Project(binary_path, auto_load_libs=False)

    try:
        main_addr = get_main_function_addr(project)
    except ValueError as exc:
        print(exc)
        return

    print(f"Analyzing 'main' at {hexify(main_addr)}")
    report = analyze_main_recursive(project, main_addr)

    out_file = "main_disassembly_report_recursive.json"
    with open(out_file, "w") as fp:
        json.dump(report, fp, indent=2)

    print(f"\nJSON written to {out_file}\n")
    print("Preview:\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
