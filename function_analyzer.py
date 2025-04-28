import angr
import json
from typing import Dict, List, Set, Any

def get_main_function_addr(project: angr.Project) -> int:
    """
    Locate the address of the 'main' function by symbol.
    """
    for sym in project.loader.main_object.symbols:
        if getattr(sym, "is_function", False) and sym.name == "main":
            return int(sym.rebased_addr)
    # Fallback: Try to find by scanning functions discovered by angr
    cfg = project.analyses.CFGFast(normalize=True)
    for func in cfg.kb.functions.values():
        if func.name == "main":
            return int(func.addr)
    raise ValueError("Could not find 'main' function.")

def get_direct_successors(block) -> List[int]:
    """
    Return all statically-known (direct) jump targets from a block.
    """
    return block.vex.constant_jump_targets

def recursive_descent(
    project: angr.Project,
    addr: int,
    visited: Set[int],
    edges: List[tuple],
    block_info: Dict[int, List[Dict[str, Any]]],
    jump_call_ret_counts: Dict[str, int],
    path: List[int],
    back_edges: Set[tuple],
    max_depth=100,
    depth=0
):
    if depth > max_depth or addr in visited:
        # Back-edge (loop) detection
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

    insns = []
    for insn in getattr(block.capstone, "insns", []):
        insns.append({
            "address": insn.address,
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str
        })
        if insn.mnemonic.startswith("j"):
            jump_call_ret_counts["jumps"] += 1
        elif insn.mnemonic.startswith("call"):
            jump_call_ret_counts["calls"] += 1
        elif insn.mnemonic.startswith("ret"):
            jump_call_ret_counts["returns"] += 1

    block_info[addr] = insns

    # Follow all direct jump/call successors
    for succ in get_direct_successors(block):
        edges.append((addr, succ))
        recursive_descent(
            project, succ, visited, edges, block_info, jump_call_ret_counts, path, back_edges, max_depth, depth + 1
        )

    # Detect back-edges from normal flow (already visited but in path)
    for succ in get_direct_successors(block):
        if succ in path:
            back_edges.add((addr, succ))

    path.pop()

def analyze_main_recursive(project: angr.Project, func_addr: int) -> Dict[str, Any]:
    """
    Analyze main function recursively: instructions, counts, loops, etc.
    """
    visited = set()
    edges = []
    block_info = {}
    back_edges = set()
    jump_call_ret_counts = {"jumps": 0, "calls": 0, "returns": 0}
    recursive_descent(
        project,
        func_addr,
        visited,
        edges,
        block_info,
        jump_call_ret_counts,
        [],
        back_edges
    )

    function_data = {
        "name": "main",
        "address": func_addr,
        "blocks": [
            {"block_address": addr, "instructions": block_info[addr]}
            for addr in sorted(block_info.keys())
        ],
        "instruction_counts": {
            "jumps": jump_call_ret_counts["jumps"],
            "calls": jump_call_ret_counts["calls"],
            "returns": jump_call_ret_counts["returns"],
            "total_blocks": len(block_info),
            "total_instructions": sum(len(block_info[addr]) for addr in block_info)
        },
        "loops": [
            {"src": src, "dst": dst}
            for (src, dst) in back_edges
        ]
    }
    return function_data

def main():
    binary_path = "helloworld.exe"  # <- Update this path!
    project = angr.Project(binary_path, auto_load_libs=False)

    try:
        main_addr = get_main_function_addr(project)
    except ValueError as e:
        print(e)
        return

    print(f"Analyzing 'main' at 0x{main_addr:x}")
    main_json = analyze_main_recursive(project, main_addr)

    with open("main_disassembly_report_recursive.json", "w") as f:
        json.dump(main_json, f, indent=2)

    print("\nPreview of JSON output for 'main':\n")
    print(json.dumps(main_json, indent=2))

if __name__ == "__main__":
    main()
