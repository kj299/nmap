-- Bitwise operators.
--
-- The eleven assertions about STRING operands here were reversed against
-- nmap's own Lua 5.4, built from `liblua/` in this repository. Upstream
-- asserted `"2" & 3.0 == 2`; PUC-Lua raises. It is not a close call:
-- `luaO_rawarith` (`lobject.c:92`) converts bitwise operands with
-- `tointegerns` -- the *no string coercion* one -- and nothing puts the string
-- back, because the metamethods `lstrlib.c` installs on the string metatable
-- (`lstrlib.c:330`) are exactly `__add __sub __mul __mod __pow __div __idiv
-- __unm`, with no bitwise entry.
--
-- The cases are kept rather than deleted: as `is_err` they now pin the real
-- behaviour instead of the wrong one, which is more coverage than before.
-- Everything not involving a string is upstream's, unchanged and still passing.

function is_err(f)
    return pcall(f) == false
end

function test1()
    return 2   & 3     == 2 and
           2.0 & 3.0   == 2
end

function test2()
    return 2   | 3     == 3 and
           2.0 | 3.0   == 3
end

function test3()
    return 2   ~ 3     == 1 and
           2.0 ~ 3.0   == 1
end

function test4()
    return ~2   == -3 and
           ~2.0 == -3
end

function test5()
    return 2   << 3     == 16 and
           2.0 << 3.0   == 16
end

function test6()
    return 145   >> 3     == 18 and
           145.0 >> 3.0   == 18 and
           -1    >> 1     == 9223372036854775807
end

-- A float converts only when its value is integral and inside the i64 range
-- (`luaV_flttointeger` in F2Ieq mode, `lvm.c:123`). 2^63 is exactly
-- representable as a double and is NOT an integer, so it must be refused even
-- though it is integral.
function test7()
    return is_err(function() return ~2.2     end) and
           is_err(function() return 2.2 & 3  end) and
           is_err(function() return 2.2 | 3  end) and
           is_err(function() return 2.2 ~ 3  end) and
           is_err(function() return 2.2 << 3 end) and
           is_err(function() return 2.2 >> 3 end) and
           is_err(function() return 2^63 | 0 end) and
           is_err(function() return (0/0) | 0 end) and
           is_err(function() return (1/0) | 0 end) and
           -(2^63) | 0 == math.mininteger
end

-- A string is never a bitwise operand, whichever side it is on and whatever it
-- would have parsed as.
function test8()
    return is_err(function() return "2" & 3.0   end) and
           is_err(function() return 2   & "3.0" end) and
           is_err(function() return "2" | 3.0   end) and
           is_err(function() return 2   | "3.0" end) and
           is_err(function() return "2" ~ 3.0   end) and
           is_err(function() return 2   ~ "3.0" end) and
           is_err(function() return ~"2"        end) and
           is_err(function() return ~"2.2"      end) and
           is_err(function() return "2" << 3.0  end) and
           is_err(function() return 2   << "3.0" end) and
           is_err(function() return "145" >> 3.0 end) and
           is_err(function() return 145 >> "3.0" end)
end

assert(
    test1() and
    test2() and
    test3() and
    test4() and
    test5() and
    test6() and
    test7() and
    test8()
)
