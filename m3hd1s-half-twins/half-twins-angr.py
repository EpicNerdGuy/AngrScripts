'''
1. Note down all addresses for all failure and success cases
2. The success block has following conditions
> length should be even 
> length should be > 7
> first half of both strings must be same
3. Set the conditions
'''

import angr
import claripy

def solve():
    binary_path = "./half-twins"
    base_addr = 0x100000
    project = angr.Project(binary_path, main_opts={'base_addr': base_addr})

    length = 10
    half = length // 2
    
    arg1_content = claripy.BVS('arg1', length * 8)
    arg2_content = claripy.BVS('arg2', length * 8)
    
    arg1 = claripy.Concat(arg1_content, claripy.BVV(0, 8))
    arg2 = claripy.Concat(arg2_content, claripy.BVV(0, 8))

    state = project.factory.entry_state(
        args=[binary_path, arg1, arg2],
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, 
                     angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )

    for b in arg1_content.chop(8) + arg2_content.chop(8):
        is_num = claripy.And(b >= ord('0'), b <= ord('9'))
        is_upper = claripy.And(b >= ord('A'), b <= ord('Z'))
        is_lower = claripy.And(b >= ord('a'), b <= ord('z'))
        state.add_constraints(claripy.Or(is_num, is_upper, is_lower))
 
 
    arg1_chars = arg1_content.chop(8)
    arg2_chars = arg2_content.chop(8)
    for i in range(half):
        state.add_constraints(arg1_chars[i] == arg2_chars[i])

    
    for i in range(half, length):
        state.add_constraints(arg1_chars[i] != arg2_chars[i])

    success_addr = 0x101355
    avoid_addrs = [0x1011c9, 0x1011fd, 0x1012d6, 0x101336, 0x101275, 0x10123f, 0x10117d]

    simgr = project.factory.simgr(state)
    print(f"[*] Solving for length {length} alphanumeric twins...")
    simgr.explore(find=success_addr, avoid=avoid_addrs)

    if simgr.found:
        sol = simgr.found[0]
        res1 = sol.solver.eval(arg1, cast_to=bytes).split(b'\0')[0].decode()
        res2 = sol.solver.eval(arg2, cast_to=bytes).split(b'\0')[0].decode()
        
        print("\n" + " MATCH FOUND ".center(40, '='))
        print(f"Arg 1: {res1}")
        print(f"Arg 2: {res2}")
        print(f"Run: ./half-twins {res1} {res2}")
        print("=" * 40)
    else:
        print("[-] Could not find a valid pair. Verify success_addr in Ghidra/IDA.")

if __name__ == "__main__":
    solve()