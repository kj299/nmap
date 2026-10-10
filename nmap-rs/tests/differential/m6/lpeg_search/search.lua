-- Adversarial slowness search for one network-facing LPeg pattern (M6.6 0b).
--
--   lua-instr search.lua PATTERN_ID CPU_SECONDS OUTDIR [SELMIN]
--
-- Needs the instrumented interpreter (build_instrumented.sh): `lpeg.__steps()`
-- returns the VM instructions and capture-evaluation steps since the last read.
--
-- Search: an evolutionary hill-climb over subjects of at most 64 KiB, seeded
-- from realistic fixtures and the pattern's grow() family, mutating bytes
-- (insert / delete / duplicate a substring / double / structural tokens /
-- splice), for CPU_SECONDS of CPU time.
-- Selection fitness: (vm + cap) / max(#s, SELMIN), SELMIN default 1024, so a
-- tiny subject (whose per-byte cost is inflated by the fixed start-up cost of
-- a match) cannot crowd large ones out of the population. Reported ratios are
-- plain (vm + cap) / #s.
--
-- Outputs, as KEY<TAB>VALUE lines on stdout:
--   SUSTAINED   the highest steps/byte over every subject evaluated with
--               #s >= SELMIN: the "max sustained steps/byte"
--   BEST_RATIO  the highest steps/byte with #s >= 64 (small subjects included)
--   GROW_EXP    log-log slope of steps against size over the grow(n) family
--   ENV_EXP     the same over the search's envelope (most steps per half-octave)
--   TAIL_EXP    ENV_EXP over subjects of at least 8 KiB only
--   PREFIX_EXP  the same over prefixes of the subject with the most steps
--   K_SUGGESTED KFACTOR (1.25) x SUSTAINED
--   SUMMARY     one tab-separated line of the above, for run_search.sh
-- and OUTDIR/best_ID.bin (BEST_RATIO's subject), sustained_ID.bin
-- (SUSTAINED's) and beststeps_ID.bin (the most steps in absolute terms).
local HERE = arg[0]:match("^(.*)/[^/]*$") or "."
local REPO = HERE .. "/../../../../.."
local M, lpeg = assert(loadfile(HERE .. "/matchers.lua"))(REPO, HERE)
local STEPS = assert(lpeg.__steps, "not the instrumented interpreter: lpeg.__steps is missing")
local id = assert(arg[1], "pattern id")
local budget = tonumber(arg[2]) or 600
local outDir = assert(arg[3], "output directory")
local SELMIN = tonumber(arg[4] or os.getenv("SELMIN") or "1024")
local KFACTOR = 1.25
local pat = assert(M[id], "unknown pattern " .. tostring(id))
local MAXLEN = 64 * 1024
local MINLEN = 64  -- BEST_RATIO and the exponent fits ignore smaller subjects
local TAILMIN = MAXLEN // 8
math.randomseed(0x5eed ^ 1 + #id)   -- deterministic per pattern

-- measure: returns vm, cap, ok. STEPS resets on each read.
STEPS()
local function measure(s)
  STEPS()
  local ok = pcall(pat.match, s)
  local vm, cap = STEPS()
  return vm, cap, ok
end
-- selection fitness (the critic's fix): divide by max(#s, SELMIN)
local function score(s)
  if #s == 0 then return -1, 0, 0 end
  local vm, cap = measure(s)
  return (vm + cap) / math.max(#s, SELMIN), vm, cap
end

-- envelope of (size -> most steps) across every subject evaluated, and the
-- sustained maximum (highest steps/byte at #s >= SELMIN)
local env = {}        -- half-octave bins
local sus = {r = 0, size = 0, s = ""}
local function record(s, vm, cap)
  local n = #s; if n == 0 then return end
  local steps = vm + cap
  local b = math.floor(math.log(n, 2) * 2 + 0.5)
  local e = env[b]
  if not e or steps > e.steps then env[b] = {size = n, steps = steps} end
  if n >= SELMIN and steps / n > sus.r then sus = {r = steps / n, size = n, s = s} end
end

-- fixture ratio (realistic subjects)
local fixR, fixInfo = 0, ""
for _, s in ipairs(pat.seeds) do
  local _, vm, cap = score(s); local r = (vm + cap) / #s
  record(s, vm, cap)
  if #s >= MINLEN and r > fixR then fixR = r; fixInfo = string.format("size=%d vm=%d cap=%d", #s, vm, cap) end
end

-- mutation alphabet as raw byte strings
local toks = pat.alpha
local function randtok() return toks[math.random(#toks)] end
local function randbyte() return string.char(math.random(0, 255)) end

local function mutate(s)
  local op = math.random(7)
  local n = #s
  if n == 0 then return randtok() end
  if op == 1 then -- insert structural token
    local i = math.random(0, n)
    return s:sub(1, i) .. randtok() .. s:sub(i + 1)
  elseif op == 2 then -- insert random byte run
    local i = math.random(0, n); local k = math.random(1, 8)
    return s:sub(1, i) .. randbyte():rep(k) .. s:sub(i + 1)
  elseif op == 3 then -- delete a range
    local i = math.random(1, n); local j = math.min(n, i + math.random(1, 16))
    return s:sub(1, i - 1) .. s:sub(j + 1)
  elseif op == 4 then -- duplicate a substring (grows repeating structure)
    local i = math.random(1, n); local len = math.random(1, math.min(n - i + 1, 512))
    local sub = s:sub(i, i + len - 1)
    local j = math.random(0, n)
    return s:sub(1, j) .. sub .. s:sub(j + 1)
  elseif op == 5 then -- double the whole thing
    return s .. s
  elseif op == 6 then -- overwrite a byte with a token
    local i = math.random(1, n)
    return s:sub(1, i - 1) .. randtok() .. s:sub(i + 1)
  else -- repeat a token many times at a point
    local i = math.random(0, n); local k = math.random(2, 64)
    return s:sub(1, i) .. randtok():rep(k) .. s:sub(i + 1)
  end
end

-- population = {s=, r=}; keep the top POP by fitness, and track the best by
-- plain ratio (#s >= MINLEN) and by absolute steps
local POP = 24
local pop = {}
for _, s in ipairs(pat.seeds) do local r = score(s); pop[#pop + 1] = {s = s, r = r} end
-- inject large grow-derived subjects so the objective is sampled at big sizes
-- too (guards against the local search under-exploring large inputs)
if pat.grow then
  for _, rr in ipairs({64, 256, 1024, 4096, 16384}) do
    local gs = pat.grow(rr)
    if #gs > 0 and #gs <= MAXLEN then
      local r, vm, cap = score(gs); record(gs, vm, cap); pop[#pop + 1] = {s = gs, r = r}
    end
  end
end
local best = {s = pop[1].s, r = 0, vm = 0, cap = 0}
local bestSteps = {s = pop[1].s, steps = 0}
local evals = 0
local function consider(child)
  if #child > MAXLEN then child = child:sub(1, MAXLEN) end
  if #child == 0 then return end
  local r, vm, cap = score(child)
  evals = evals + 1
  record(child, vm, cap)
  pop[#pop + 1] = {s = child, r = r}
  local tr = (vm + cap) / #child
  if #child >= MINLEN and tr > best.r then best = {s = child, r = tr, vm = vm, cap = cap} end
  if vm + cap > bestSteps.steps then bestSteps = {s = child, steps = vm + cap, size = #child} end
end
local t0 = os.clock()
while os.clock() - t0 < budget do
  for _ = 1, 40 do consider(mutate(pop[math.random(#pop)].s)) end
  -- occasional splice
  for _ = 1, 6 do
    local a = pop[math.random(#pop)].s; local bb = pop[math.random(#pop)].s
    local i = math.random(0, #a); local j = math.random(0, #bb)
    consider(a:sub(1, i) .. bb:sub(j + 1))
  end
  table.sort(pop, function(x, y) return x.r > y.r end)
  while #pop > POP do pop[#pop] = nil end
  -- keep diversity: occasionally reinject a seed
  if math.random() < 0.1 then pop[#pop + 1] = {s = pat.seeds[math.random(#pat.seeds)], r = 0} end
end

local function fitExp(xs, ys)
  local n = #xs; local sx, sy, sxx, sxy = 0, 0, 0, 0
  for i = 1, n do
    local lx, ly = math.log(xs[i]), math.log(math.max(ys[i], 1))
    sx = sx + lx; sy = sy + ly; sxx = sxx + lx * lx; sxy = sxy + lx * ly
  end
  return (n * sxy - sx * sy) / (n * sxx - sx * sx)
end

-- growth test on the hand-authored adversarial family grow(n)
local gN, gSize, gSteps = {}, {}, {}
local function growPoint(r)
  local s = pat.grow(r)
  if #s == 0 or #s > MAXLEN then return #s <= MAXLEN end
  local vm, cap = measure(s)
  gN[#gN + 1] = r; gSize[#gSize + 1] = #s; gSteps[#gSteps + 1] = vm + cap
  record(s, vm, cap)
  return true
end
if pat.grow then
  local r = 1
  for _ = 1, 40 do
    if not growPoint(r) then break end
    r = r * 2
  end
  for _, r2 in ipairs({3, 6, 12, 24, 48, 96, 192, 384, 768, 1536, 3072, 6144, 12288}) do growPoint(r2) end
end
local gx, gy = {}, {}
for i = 1, #gSize do if gSize[i] >= MINLEN then gx[#gx + 1] = gSize[i]; gy[#gy + 1] = gSteps[i] end end
local growExp = (#gx >= 3) and fitExp(gx, gy) or -1

-- exponent over prefixes of the subject with the most steps: tests the
-- structure the search actually found, not a hand-authored family
local px, py, prows = {}, {}, {}
do
  local full = bestSteps.s
  for _, frac in ipairs({1/32, 1/16, 1/8, 1/4, 1/2, 1}) do
    local L = math.floor(#full * frac)
    if L >= SELMIN then
      local vm, cap = measure(full:sub(1, L))
      px[#px + 1] = L; py[#py + 1] = vm + cap
      prows[#prows + 1] = {L, vm + cap}
      record(full:sub(1, L), vm, cap)
    end
  end
end
local prefixExp = (#px >= 3) and fitExp(px, py) or -1

-- exponent over the search's envelope (upper frontier), size >= MINLEN
local ex, ey = {}, {}
local bins = {}; for k in pairs(env) do bins[#bins + 1] = k end; table.sort(bins)
for _, k in ipairs(bins) do local e = env[k]; if e.size >= MINLEN then ex[#ex + 1] = e.size; ey[#ey + 1] = e.steps end end
local envExp = (#ex >= 3) and fitExp(ex, ey) or -1
-- the same over the envelope's top three octaves only (>= MAXLEN/8): start-up
-- cost is negligible there and the search spends most of its effort there, so
-- this is the slope to trust at short budgets
local tx, ty = {}, {}
for _, k in ipairs(bins) do local e = env[k]; if e.size >= TAILMIN then tx[#tx + 1] = e.size; ty[#ty + 1] = e.steps end end
local tailExp = (#tx >= 3) and fitExp(tx, ty) or -1

local function w(path, data) local f = assert(io.open(path, "wb")); f:write(data); f:close() end
w(outDir .. "/best_" .. id .. ".bin", best.s)
w(outDir .. "/sustained_" .. id .. ".bin", sus.s)
w(outDir .. "/beststeps_" .. id .. ".bin", bestSteps.s)

local K = KFACTOR * sus.r
local out = io.write
out(string.format("PATTERN\t%s\n", id))
out(string.format("SITE\t%s\n", pat.site))
out(string.format("BUDGET\t%g\tSELMIN=%d\n", budget, SELMIN))
out(string.format("EVALS\t%d\n", evals))
out(string.format("FIXTURE_RATIO\t%.4f\t%s\n", fixR, fixInfo))
out(string.format("SUSTAINED\t%.4f\tsize=%d\n", sus.r, sus.size))
out(string.format("BEST_RATIO\t%.4f\tsize=%d\tvm=%d\tcap=%d\n", best.r, #best.s, best.vm, best.cap))
out(string.format("BEST_ABS_STEPS\t%d\tsize=%d\tratio=%.4f\n", bestSteps.steps, bestSteps.size or 0,
  bestSteps.steps / math.max(bestSteps.size or 1, 1)))
out(string.format("GROW_EXP\t%.3f\tpoints=%d\n", growExp, #gx))
out(string.format("ENV_EXP\t%.3f\tpoints=%d\n", envExp, #ex))
out(string.format("TAIL_EXP\t%.3f\tpoints=%d\n", tailExp, #tx))
out(string.format("PREFIX_EXP\t%.3f\tpoints=%d\n", prefixExp, #px))
out(string.format("K_SUGGESTED\t%.2f\t=%.2f*SUSTAINED\n", K, KFACTOR))
out("GROW_TABLE\tn\tsize\tsteps\tsteps_per_byte\n")
for i = 1, #gSize do
  out(string.format("GROW_ROW\t%d\t%d\t%d\t%.3f\n", gN[i], gSize[i], gSteps[i], gSteps[i] / gSize[i]))
end
out("ENV_TABLE\tsize\tsteps\tsteps_per_byte\n")
for _, k in ipairs(bins) do local e = env[k]
  out(string.format("ENV_ROW\t%d\t%d\t%.3f\n", e.size, e.steps, e.steps / e.size)) end
out("PREFIX_TABLE\tlen\tsteps\tsteps_per_byte\n")
for _, r in ipairs(prows) do out(string.format("PREFIX_ROW\t%d\t%d\t%.3f\n", r[1], r[2], r[2] / r[1])) end
-- id, evals, sustained, at size, best ratio (>= 64 B), grow, env, prefix, tail, K
out(string.format("SUMMARY\t%s\t%d\t%.2f\t%d\t%.2f\t%.3f\t%.3f\t%.3f\t%.3f\t%.2f\n",
  id, evals, sus.r, sus.size, best.r, growExp, envExp, prefixExp, tailExp, K))
