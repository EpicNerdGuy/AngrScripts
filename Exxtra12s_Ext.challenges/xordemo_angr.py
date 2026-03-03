#!/usr/bin/python3

import angr
import claripy
import sys

def solve():
    proj = angr.Project("./xordemo", auto_load_libs=False, main_opts={'base_addr': 0x100000})

    PASS_LEN = 16 
    sym_password = claripy.BVS("password", PASS_LEN * 8)

    state = proj.factory.entry_state(args=["./xordemo", sym_password])

    for byte in sym_password.chop(8):
        state.add_constraints(byte >= 0x21) # '!'
        state.add_constraints(byte <= 0x7e) # '~'

    
    simgr = proj.factory.simulation_manager(state)

    print("[ * ] Searching for the password...")
    simgr.explore(find=lambda s: b"Jackpot" in s.posix.dumps(1))    

    if simgr.found:
        sol = simgr.found[0]
        # eval returns the bytes; we decode and strip any trailing nulls
        results = sol.solver.eval_upto(sym_password, 5, cast_to=bytes)
        for r in results:
            print(f"Possible: {r}")
    else:
        print("[ x ] Failed to find path.")

if __name__ == "__main__":
    solve()