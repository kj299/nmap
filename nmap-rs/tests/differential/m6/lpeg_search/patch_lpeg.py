#!/usr/bin/env -S python3 -I -B
"""Write an instrumented COPY of lpeg.c that counts LPeg's work.

    patch_lpeg.py SRC_LPEG_C DST_LPEG_C

Two counters are added: one per VM instruction (the top of the match loop)
and one per capture-evaluation step (each pushcapture call). `lpeg.__steps()`
returns both, as (vm_steps, cap_steps), and resets them. Every edit is
anchored on text that must occur exactly once; a moved anchor is a hard
failure, so the counters can never silently go missing. SRC is only read.
"""
import os
import sys

if len(sys.argv) != 3:
    sys.exit("usage: patch_lpeg.py SRC_LPEG_C DST_LPEG_C")
src_path, dst_path = sys.argv[1], sys.argv[2]
if os.path.realpath(src_path) == os.path.realpath(dst_path):
    sys.exit("refusing to patch lpeg.c in place: give a separate destination")
with open(src_path, encoding="latin-1") as fh:
    src = fh.read()


def once(anchor, what):
    n = src.count(anchor)
    if n != 1:
        sys.exit("patch_lpeg.py: %s anchor occurs %d times (expected 1): %r" % (what, n, anchor[:60]))


# 1. Counters, declared before the first use (pushcapture's forward declaration).
decl = r'''
/* ---- M6.6 0b adversarial instrumentation (lpeg_search; never in the tree) ---- */
static unsigned long long lpeg_vm_steps = 0;
static unsigned long long lpeg_cap_steps = 0;
/* ------------------------------------------------------------------------------ */
'''
anchor = 'static int pushcapture (CapState *cs);'
once(anchor, "pushcapture forward declaration")
src = src.replace(anchor, decl + '\n' + anchor, 1)

# 2. One count per VM instruction, at the top of the match loop.
vm_anchor = '''  lua_pushlightuserdata(L, stackbase);
  for (;;) {'''
once(vm_anchor, "VM loop")
src = src.replace(vm_anchor, vm_anchor + '\n    lpeg_vm_steps++;', 1)

# 3. One count per capture-evaluation step (each pushcapture call).
cap_anchor = '''static int pushcapture (CapState *cs) {
  lua_State *L = cs->L;'''
once(cap_anchor, "pushcapture body")
src = src.replace(cap_anchor, cap_anchor + '\n  lpeg_cap_steps++;', 1)

# 4. The accessor: lpeg.__steps() -> vm_steps, cap_steps, and reset both.
accessor = r'''
static int lp_steps (lua_State *L) {
  lua_pushnumber(L, (lua_Number)lpeg_vm_steps);
  lua_pushnumber(L, (lua_Number)lpeg_cap_steps);
  lpeg_vm_steps = 0;
  lpeg_cap_steps = 0;
  return 2;
}
'''
reg_anchor = 'static struct luaL_Reg pattreg[] = {'
once(reg_anchor, "pattreg table")
src = src.replace(reg_anchor, accessor + '\n' + reg_anchor, 1)
ptree = '  {"ptree", lp_printtree},'
once(ptree, "ptree registration")
src = src.replace(ptree, '  {"__steps", lp_steps},\n' + ptree, 1)

with open(dst_path, "w", encoding="latin-1") as fh:
    fh.write(src)
print("patched copy written: %s" % dst_path)
