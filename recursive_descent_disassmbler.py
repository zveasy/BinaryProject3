import angr
import networkx as nx
from typing import Set, List, Dict

def get_main_addr(project: angr.Project) -> int:
    """
    Find the address of the 'main' function symbol in the binary.
    """
    for sym in project.loader.main_object.symbols:
        if sym.name == 'main' and getattr(sym, "is_function", False):
            return int(sym.rebased_addr)
    raise RuntimeError("Could not find main symbol!")

def get_direct_successors(block: angr.block.Block) -> List[int]:
    """
    Return all statically-known (direct) jump targets from a block.
    """
    return list(getattr(block.vex, "constant_jump_targets", []))

def resolve_indirect_targets(project: angr.Project, addr: int) -> Set[int]:
    """
    Indirect resolution not supported in this minimal example.
    """
    print(f"  [Warning] Indirect target resolution for 0x{addr:x} not supported in this mode.")
    return set()

def recursive_descent(
    project: angr.Project,
    addr: int,
    visited: Set[int],
    cfg_graph: nx.DiGraph,
    max_depth: int = 50,
    depth: int = 0,
    code_min: int = 0,
    code_max: int = 0
) -> None:
    """
    Recursively disassemble and build the CFG, only within the main code section.
    """
    if depth > max_depth or addr in visited:
        return
    # Restrict to code section (skip CRT, imports, etc.)
    if not (code_min <= addr < code_max):
        print(f"{'  '*depth}Skipping 0x{addr:x} (outside .text section)")
        return
    visited.add(addr)

    try:
        block: angr.block.Block = project.factory.block(addr)
    except Exception:
        print(f"{'  '*depth}Could not disassemble 0x{addr:x}")
        return

    indent = "  " * depth
    print(f"{indent}Disassembling block at 0x{addr:x}:")
    for insn in getattr(block.capstone, "insns", []):
        insn_addr = getattr(insn, "address", None)
        mnemonic = getattr(insn, "mnemonic", "")
        op_str = getattr(insn, "op_str", "")
        print(f"{indent}  0x{insn_addr:x}: {mnemonic} {op_str}")

    cfg_graph.add_node(addr)

    # Follow all direct jump/call successors
    for succ in get_direct_successors(block):
        if code_min <= succ < code_max:
            cfg_graph.add_edge(addr, succ)
            recursive_descent(project, succ, visited, cfg_graph, max_depth, depth + 1, code_min, code_max)

    # Handle direct calls by checking the last instruction (for simplicity)
    insns = getattr(block.capstone, "insns", [])
    if insns:
        last_insn = insns[-1]
        mnemonic = getattr(last_insn, "mnemonic", "")
        op_str = getattr(last_insn, "op_str", "")
        if mnemonic.startswith('call'):
            try:
                callee = int(op_str, 16)
                if code_min <= callee < code_max:
                    cfg_graph.add_edge(addr, callee)
                    recursive_descent(project, callee, visited, cfg_graph, max_depth, depth + 1, code_min, code_max)
            except ValueError:
                # Try to resolve indirect call
                indirect_targets = resolve_indirect_targets(project, addr)
                for callee in indirect_targets:
                    if code_min <= callee < code_max:
                        cfg_graph.add_edge(addr, callee)
                        recursive_descent(project, callee, visited, cfg_graph, max_depth, depth + 1, code_min, code_max)

    # Handle indirect jumps (minimal example, just warn)
    jumpkind = getattr(block.vex, "jumpkind", "")
    constant_jump_targets = getattr(block.vex, "constant_jump_targets", [])
    if (jumpkind.startswith('Ijk_Call') or jumpkind.startswith('Ijk_Boring')) and not constant_jump_targets:
        indirect_targets = resolve_indirect_targets(project, addr)
        for target in indirect_targets:
            if code_min <= target < code_max and target not in visited:
                cfg_graph.add_edge(addr, target)
                recursive_descent(project, target, visited, cfg_graph, max_depth, depth + 1, code_min, code_max)

def main() -> None:
    binary_path: str = 'helloworld.exe'  # <- Update this to your binary path!
    project: angr.Project = angr.Project(binary_path, auto_load_libs=False)
    visited: Set[int] = set()
    cfg_graph: nx.DiGraph = nx.DiGraph()

    # Get address range of the .text (code) section for the main binary
    text_section = project.loader.main_object.sections_map.get('.text')
    if not text_section:
        print("Could not find .text section in binary!")
        return
    code_min = int(text_section.min_addr)
    code_max = int(text_section.max_addr)

    # Find the address of main
    try:
        main_addr = get_main_addr(project)
    except RuntimeError as e:
        print(str(e))
        return

    print(f"Disassembling only 'main' at 0x{main_addr:x} (and code it calls, only in .text section [{code_min:x}, {code_max:x}))")
    recursive_descent(project, main_addr, visited, cfg_graph, code_min=code_min, code_max=code_max)

    nx.drawing.nx_pydot.write_dot(cfg_graph, "angr_disassembly_cfg.dot")
    print("CFG written to angr_disassembly_cfg.dot (view with Graphviz or xdot).")

if __name__ == '__main__':
    main()
