use std::hash::{Hash, Hasher};

use gc_arena::Collect;

use crate::compiler::string_utils::{read_float, read_integer, trim_whitespace};

#[derive(Debug, Copy, Clone, Collect)]
#[collect(no_drop)]
pub enum Constant<S> {
    Nil,
    Boolean(bool),
    Integer(i64),
    Number(f64),
    String(S),
}

impl<S> Constant<S> {
    pub fn to_bool(&self) -> bool {
        match self {
            Self::Nil => false,
            Self::Boolean(false) => false,
            _ => true,
        }
    }

    pub fn not(&self) -> Constant<S> {
        Constant::Boolean(!self.to_bool())
    }

    pub fn as_string_ref(&self) -> Constant<&S> {
        match self {
            Constant::Nil => Constant::Nil,
            Constant::Boolean(b) => Constant::Boolean(*b),
            Constant::Integer(i) => Constant::Integer(*i),
            Constant::Number(n) => Constant::Number(*n),
            Constant::String(s) => Constant::String(s),
        }
    }

    pub fn map_string<S2>(self, f: impl FnOnce(S) -> S2) -> Constant<S2> {
        match self {
            Constant::Nil => Constant::Nil,
            Constant::Boolean(b) => Constant::Boolean(b),
            Constant::Integer(i) => Constant::Integer(i),
            Constant::Number(n) => Constant::Number(n),
            Constant::String(s) => Constant::String(f(s)),
        }
    }
}

/// `luaV_flttointeger` in `F2Ieq` mode (`lvm.c:123`), whose range test is `lua_numbertointeger`
/// (`luaconf.h:432`): `n >= -2^63 && n < 2^63`.
///
/// The strict upper bound is the reason this is not a cast. `2^63` is exactly representable as a
/// double but is not an `i64`, and Rust's `as` saturates it to `i64::MAX` rather than refusing it
/// — which then converts back to `2^63` and passes a round-trip check. So `2^63 | 0` answered
/// `maxinteger` here where Lua raises "number has no integer representation". `-2^63` is accepted,
/// because `i64::MIN` does have an exact representation; the asymmetry is real, not a typo, and
/// `luaconf.h` says so at the site.
fn float_to_integer(n: f64) -> Option<i64> {
    /// `-2^63`, exact as a double.
    const MIN: f64 = -9223372036854775808.0;
    /// `2^63`, one past `i64::MAX` and exact as a double.
    const LIMIT: f64 = 9223372036854775808.0;
    // `n == n.floor()` is the `F2Ieq` test, and it rejects NaN for free.
    if n >= MIN && n < LIMIT && n == n.floor() {
        Some(n as i64)
    } else {
        None
    }
}

impl<S: AsRef<[u8]>> Constant<S> {
    /// Converts the given constant to an integer or number, if possible.
    pub fn to_numeric(&self) -> Option<Constant<S>> {
        match self {
            &Self::Integer(a) => Some(Constant::Integer(a)),
            &Self::Number(a) => Some(Constant::Number(a)),
            Self::String(a) => {
                let a = trim_whitespace(a.as_ref());
                if let Some(i) = read_integer(a) {
                    Some(Constant::Integer(i))
                } else if let Some(n) = read_float(a) {
                    Some(Constant::Number(n))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Interprets Numbers, Integers, and Strings as a Number, if possible.
    pub fn to_number(&self) -> Option<f64> {
        match self.to_numeric() {
            Some(Self::Integer(a)) => Some(a as f64),
            Some(Self::Number(a)) => Some(a),
            _ => None,
        }
    }

    /// Interprets Numbers, Integers, and Strings as an Integer, if possible.
    ///
    /// This is `luaV_tointeger` (`lvm.c:154`) — the string-coercing one, which is what
    /// `math.tointeger`, `select` and the numeric `for` use. The operators do NOT use it; see
    /// [`Constant::to_integer_no_string`].
    pub fn to_integer(&self) -> Option<i64> {
        match self.to_numeric() {
            Some(Self::Integer(a)) => Some(a),
            Some(Self::Number(a)) => float_to_integer(a),
            _ => None,
        }
    }

    /// `tointegerns` (`lvm.h:68`) — "convert an object to an integer (without string coercion)".
    ///
    /// The `ns` suffix is the whole point. `luaO_rawarith` (`lobject.c:89`) reaches for this one,
    /// not the string-coercing `tointeger`, for every bitwise operator, and nothing puts the
    /// string back: the arithmetic metamethods `lstrlib.c` installs on the string metatable are
    /// exactly `__add __sub __mul __mod __pow __div __idiv __unm` (`lstrlib.c:330`) — no
    /// `__band`, `__bor`, `__bxor`, `__shl`, `__shr` or `__bnot`. So `'10' | 0` is an *error* in
    /// Lua, where this VM used to answer 10.
    ///
    /// That difference is not cosmetic in a scanner. NSE's protocol libraries mask and shift
    /// values lifted out of hostile packets, and a field that arrives as a string should stop the
    /// script with a catchable error rather than silently take the arithmetic path.
    fn to_integer_no_string(&self) -> Option<i64> {
        match *self {
            Self::Integer(a) => Some(a),
            Self::Number(a) => float_to_integer(a),
            _ => None,
        }
    }

    // Mathematical operators
    //
    // Every one of these coerces a numeric string operand FIRST, with `to_numeric`, and only then
    // decides between the integer and the float path. Deciding first, as this type used to, loses
    // the subtype: `'10' + 1` fell to the catch-all arm, went through `to_number`, and answered
    // float `11.0` where Lua answers integer `11`.
    //
    // Lua reaches the same place by a longer route. `luaO_rawarith` (`lobject.c:89`) never
    // coerces a string at all — it uses `tonumberns`, the no-string conversion — so a string
    // operand makes the raw operation fail and `luaO_arith` falls through to the metamethod. The
    // metamethod is `lstrlib.c`'s `arith` (`lstrlib.c:283`), which converts each operand with
    // `lua_stringtonumber` and then re-enters `lua_arith` with two *numbers*. And
    // `lua_stringtonumber` is `luaO_str2num` (`lobject.c:308`), which tries `l_str2int` before
    // `l_str2d` — so `'10'` arrives as an integer, and integer + integer stays an integer.
    //
    // This matters past cosmetics: NSE's binary-protocol libraries branch on `math.type` over
    // values parsed out of packets, and `//` and `%` on a float do not give the same answer as on
    // an integer once the magnitudes pass 2^53.

    pub fn add(&self, rhs: &Self) -> Option<Self> {
        Some(match (self.to_numeric()?, rhs.to_numeric()?) {
            (Self::Integer(a), Self::Integer(b)) => Self::Integer(a.wrapping_add(b)),
            (a, b) => Self::Number(a.to_number()? + b.to_number()?),
        })
    }

    pub fn subtract(&self, rhs: &Self) -> Option<Self> {
        Some(match (self.to_numeric()?, rhs.to_numeric()?) {
            (Self::Integer(a), Self::Integer(b)) => Self::Integer(a.wrapping_sub(b)),
            (a, b) => Self::Number(a.to_number()? - b.to_number()?),
        })
    }

    pub fn multiply(&self, rhs: &Self) -> Option<Self> {
        Some(match (self.to_numeric()?, rhs.to_numeric()?) {
            (Self::Integer(a), Self::Integer(b)) => Self::Integer(a.wrapping_mul(b)),
            (a, b) => Self::Number(a.to_number()? * b.to_number()?),
        })
    }

    /// This operation always returns a Number, even when called with Integer arguments.
    pub fn float_divide(&self, rhs: &Self) -> Option<Self> {
        Some(Self::Number(self.to_number()? / rhs.to_number()?))
    }

    /// This operation returns an Integer only if both arguments are Integers. Rounding is towards
    /// negative infinity.
    pub fn floor_divide(&self, rhs: &Self) -> Option<Self> {
        match (self.to_numeric()?, rhs.to_numeric()?) {
            (Self::Integer(a), Self::Integer(b)) => {
                if b == 0 {
                    None
                } else {
                    // Wrapping version of std's div_floor
                    let d = a.wrapping_div(b);
                    let r = a.wrapping_rem(b);
                    let d = if (r > 0 && b < 0) || (r < 0 && b > 0) {
                        // Cannot overflow: `d == i64::MIN` only for `a == i64::MIN` with
                        // `b == 1` or `b == -1`, and both leave `r == 0`, so this branch is
                        // unreachable for them. `wrapping_sub` states that rather than resting
                        // on it -- under this workspace's `overflow-checks = true`, a plain `-`
                        // here would be a process abort if the reasoning were ever wrong.
                        debug_assert!(d.checked_sub(1).is_some(), "{d} - 1 overflowed");
                        d.wrapping_sub(1)
                    } else {
                        d
                    };
                    Some(Self::Integer(d))
                }
            }
            (a, b) => Some(Self::Number((a.to_number()? / b.to_number()?).floor())),
        }
    }

    /// Computes the Lua modulus (`%`) operator. This is unlike Rust's `%` operator which computes
    /// the remainder.
    ///
    /// Both halves are ported from PUC-Lua rather than derived: the integer path from `luaV_mod`
    /// (`lvm.c:748-760`) and the float path from `luai_nummod` (`llimits.h:332-336`). The previous
    /// implementation computed `((a % b) + b) % b` for both, which is the obvious formula and is
    /// wrong twice over.
    ///
    /// **It aborted the process.** `a % b` traps for `i64::MIN % -1`, and the `+ b` overflows for
    /// operands like `-1 % i64::MIN`. Neither is a Lua error a script can `pcall` — a
    /// host-language panic escapes `pcall` entirely — and `meta_ops` routes *runtime* arithmetic
    /// through here, not merely constant folding, so any Lua `%` on attacker-influenced integers
    /// could take the interpreter down. C avoids the first by special-casing `-1`, and says so at
    /// the site: *"m % -1 == 0; avoid overflow with 0x80000...%-1"*.
    ///
    /// **It was wrong on infinities.** `5.0 % inf` is `5.0` in Lua and `NaN` under the old
    /// formula, because `(5 + inf) % inf` is `inf % inf`.
    pub fn modulo(&self, rhs: &Self) -> Option<Self> {
        match (self.to_numeric()?, rhs.to_numeric()?) {
            (Self::Integer(a), Self::Integer(b)) => {
                if b == 0 {
                    // `n % 0` is a Lua *error*, which a script can catch. Returning None is how
                    // this type reports that; it must never become a panic.
                    None
                } else if b == -1 {
                    // The special case that exists to avoid the trap, not for speed.
                    Some(Self::Integer(0))
                } else {
                    // `b` is now neither 0 nor -1, so `%` cannot trap.
                    let r = a % b;
                    Some(Self::Integer(if r != 0 && (r ^ b) < 0 {
                        // Rounding correction, for when `a / b` would be a negative non-integer.
                        //
                        // This cannot overflow: `|r| < |b|` because `r` is a remainder of `b`, and
                        // the branch condition says `r` and `b` have opposite signs, so `r + b`
                        // lies strictly between `b` and `-b`. `wrapping_add` rather than `+`
                        // anyway, because if that reasoning is ever wrong the failure should be a
                        // wrong number in one script, not a dead scan; the debug assertion is
                        // what makes it loud in testing.
                        debug_assert!(r.checked_add(b).is_some(), "{r} + {b} overflowed");
                        r.wrapping_add(b)
                    } else {
                        r
                    }))
                }
            }
            (a, b) => {
                let (a, b) = (a.to_number()?, b.to_number()?);
                // `luai_nummod`: fmod, then one sign correction. Rust's `%` on f64 IS fmod.
                let m = a % b;
                let correct = if m > 0.0 { b < 0.0 } else { m < 0.0 && b > 0.0 };
                Some(Self::Number(if correct { m + b } else { m }))
            }
        }
    }

    /// This operation always returns a Number, even when called with Integer arguments.
    pub fn exponentiate(&self, rhs: &Self) -> Option<Self> {
        Some(Self::Number(self.to_number()?.powf(rhs.to_number()?)))
    }

    pub fn negate(&self) -> Option<Self> {
        Some(match self.to_numeric()? {
            Self::Integer(a) => Self::Integer(a.wrapping_neg()),
            Self::Number(a) => Self::Number(-a),
            // `to_numeric` returns only those two variants, so this is unreachable. Returning
            // `None` rather than asserting keeps a future edit to `to_numeric` a Lua error
            // instead of a process abort.
            _ => return None,
        })
    }

    // Bitwise operators

    pub fn bitwise_not(&self) -> Option<Self> {
        Some(Self::Integer(!self.to_integer_no_string()?))
    }

    pub fn bitwise_and(&self, rhs: &Self) -> Option<Self> {
        Some(Self::Integer(
            self.to_integer_no_string()? & rhs.to_integer_no_string()?,
        ))
    }

    pub fn bitwise_or(&self, rhs: &Self) -> Option<Self> {
        Some(Self::Integer(
            self.to_integer_no_string()? | rhs.to_integer_no_string()?,
        ))
    }

    pub fn bitwise_xor(&self, rhs: &Self) -> Option<Self> {
        Some(Self::Integer(
            self.to_integer_no_string()? ^ rhs.to_integer_no_string()?,
        ))
    }

    /// Ported from `luaV_shiftl` (`lvm.c:780-790`).
    ///
    /// Lua defines shifts over the whole `i64` range of counts, with no error
    /// case: a count at or past the word size gives 0, and a NEGATIVE count
    /// reverses the direction. Both shifts are logical, not arithmetic --
    /// PUC-Lua's `intop` casts through `lua_Unsigned` -- so `-1 >> 1` is
    /// `maxinteger`, not `-1`.
    ///
    /// The previous implementation refused a negative count outright, which
    /// turned 180 of the 2,955 cross-product corpus cases into a runtime error
    /// where Lua produces a value.
    fn shift_left_i64(x: i64, y: i64) -> i64 {
        const NBITS: i64 = i64::BITS as i64;
        if y < 0 {
            // Shift right. The `<= -NBITS` test runs FIRST, which is what makes
            // `-y` safe below: it excludes `i64::MIN`, the one value whose
            // negation overflows.
            if y <= -NBITS {
                0
            } else {
                ((x as u64) >> (-y) as u32) as i64
            }
        } else if y >= NBITS {
            0
        } else {
            ((x as u64) << y as u32) as i64
        }
    }

    pub fn shift_left(&self, rhs: &Self) -> Option<Self> {
        Some(Self::Integer(Self::shift_left_i64(
            self.to_integer_no_string()?,
            rhs.to_integer_no_string()?,
        )))
    }

    pub fn shift_right(&self, rhs: &Self) -> Option<Self> {
        // `luaV_shiftr(x, y)` is `luaV_shiftl(x, intop(-, 0, y))` (`lvm.h:116`),
        // and `intop` negates through the unsigned type -- so the negation
        // WRAPS. That is not incidental: for `y == i64::MIN` the wrap leaves
        // `i64::MIN`, still negative, so the count stays in the shift-right
        // branch and yields 0. A checked negation would trap on exactly that
        // value, which is the operand an attacker would reach for.
        Some(Self::Integer(Self::shift_left_i64(
            self.to_integer_no_string()?,
            rhs.to_integer_no_string()?.wrapping_neg(),
        )))
    }

    // Comparison operators

    pub fn is_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Nil, Self::Nil) => true,
            (Self::Nil, _) => false,

            (Self::Boolean(a), Self::Boolean(b)) => a == b,
            (Self::Boolean(_), _) => false,

            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Integer(a), Self::Number(b)) => *a as f64 == *b,
            (Self::Integer(_), _) => false,

            (Self::Number(a), Self::Number(b)) => a == b,
            (Self::Number(a), Self::Integer(b)) => *b as f64 == *a,
            (Self::Number(_), _) => false,

            (Self::String(a), Self::String(b)) => a.as_ref() == b.as_ref(),
            (Self::String(_), _) => false,
        }
    }

    pub fn less_than(&self, rhs: &Self) -> Option<bool> {
        Some(match (self, rhs) {
            (Self::Integer(a), Self::Integer(b)) => a < b,
            (Self::Integer(a), Self::Number(b)) => (*a as f64) < *b,
            (Self::Number(a), Self::Number(b)) => a < b,
            (Self::Number(a), Self::Integer(b)) => *a < *b as f64,
            (Self::String(a), Self::String(b)) => a.as_ref() < b.as_ref(),
            _ => return None,
        })
    }

    pub fn less_equal(&self, rhs: &Self) -> Option<bool> {
        Some(match (self, rhs) {
            (Self::Integer(a), Self::Integer(b)) => a <= b,
            (Self::Integer(a), Self::Number(b)) => (*a as f64) <= *b,
            (Self::Number(a), Self::Number(b)) => a <= b,
            (Self::Number(a), Self::Integer(b)) => *a <= *b as f64,
            (Self::String(a), Self::String(b)) => a.as_ref() <= b.as_ref(),
            _ => return None,
        })
    }
}

impl<S: AsRef<[u8]>> PartialEq for Constant<S> {
    fn eq(&self, other: &Self) -> bool {
        self.is_equal(other)
    }
}

/// Wrapper for a `Constant` that implements Hash and Eq, and only compares equal when the types are
/// bit for bit identical.
#[derive(Debug, Copy, Clone, Collect)]
#[collect(no_drop)]
pub struct IdenticalConstant<S>(pub Constant<S>);

impl<S> From<Constant<S>> for IdenticalConstant<S> {
    fn from(value: Constant<S>) -> Self {
        Self(value)
    }
}

impl<S: AsRef<[u8]>> PartialEq for IdenticalConstant<S> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Constant::Nil, Constant::Nil) => true,
            (Constant::Nil, _) => false,

            (Constant::Boolean(a), Constant::Boolean(b)) => a == b,
            (Constant::Boolean(_), _) => false,

            (Constant::Integer(a), Constant::Integer(b)) => a == b,
            (Constant::Integer(_), _) => false,

            (Constant::Number(a), Constant::Number(b)) => a.to_bits() == b.to_bits(),
            (Constant::Number(_), _) => false,

            (Constant::String(a), Constant::String(b)) => a.as_ref() == b.as_ref(),
            (Constant::String(_), _) => false,
        }
    }
}

impl<S: AsRef<[u8]>> Eq for IdenticalConstant<S> {}

impl<S: AsRef<[u8]>> Hash for IdenticalConstant<S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            Constant::Nil => {
                Hash::hash(&0, state);
            }
            Constant::Boolean(b) => {
                Hash::hash(&1, state);
                b.hash(state);
            }
            Constant::Integer(i) => {
                Hash::hash(&2, state);
                i.hash(state);
            }
            Constant::Number(n) => {
                Hash::hash(&3, state);
                n.to_bits().hash(state);
            }
            Constant::String(s) => {
                Hash::hash(&4, state);
                s.as_ref().hash(state);
            }
        }
    }
}
