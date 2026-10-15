# RetypePlus

Apply types that IDA's own **Set type** (Y) cannot handle — in particular the C++
template names that come in with a PDB, such as `std::_Func_base<char const *>`.

## The problem

When you import symbols from a PDB, IDA creates local types whose names contain
angle brackets:

```text
std::_Func_base<char const *>
std::function<void __cdecl(int)>
_Wrap<unsigned int,2>
```

Those types are real and usable — they sit in the local type library, and the
decompiler will happily use them. But IDA's **declaration parser rejects `<` and `>`**
inside a type name:

```text
parse_decls("struct std::_Func_base<char const *> { ... };")  ->  2 (failure)
tinfo_t().parse("std::_Func_base<char const *>")              ->  failure
```

The result is a dead end in the UI: you press `Y`, type the name, and IDA says the
type does not exist. There is no way to apply it.

RetypePlus sidesteps the parser entirely. It looks the type up by name with
`tinfo_t.get_named_type()`, which does no syntax checking, so any type already
present in the TIL can be applied.

## What it also fixes

Two things that broke in IDA 9.4 while making this work:

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Sorry, cannot change argument type.` / `Please edit the function prototype instead` | 9.4 refuses `vdui_t.set_lvar_type()` for function arguments | rewrite the prototype via `tinfo_t.set_funcarg_type()` + `apply_tinfo()` |
| Changing a struct member silently does nothing | the old code mutated a throwaway in-memory copy of the `tinfo_t` | rebuild the struct and write it back with `set_named_type()` |

## Install

Copy `RetypePlus.py` into IDA's `plugins` directory:

```text
<IDA install>/plugins/RetypePlus.py
```

Restart IDA. The log shows:

```text
[+] ApplyNamedType loaded (Ctrl+Shift+Y)
```

The action also appears under **Edit/Plugins/Apply Named Type**.

## Use

Press **Ctrl+Shift+Y**, then type the type name. The name may include pointer
levels and builtin/array syntax:

```text
std::_Func_base<char const *>
std::_Func_base<char const *> *
std::_Func_base<char const *> **
unsigned int
void *
int[4]
```

Where the cursor is decides what gets retyped:

| Window | Cursor on | Result |
| --- | --- | --- |
| Pseudocode | a local variable | `set_lvar_type` |
| Pseudocode | a **function argument** | function prototype is rewritten |
| Pseudocode | a global / expression | `apply_tinfo` at that address |
| Local Types | a struct/union member | struct is rebuilt with the new member type |
| Disassembly | an address | `apply_tinfo` at the cursor |

### Example

Decompiled code shows an argument typed as `_DWORD *` that is really a pointer to a
PDB template type:

```c
__int64 __fastcall consume(_DWORD *a1)
```

Put the cursor on `a1`, press `Ctrl+Shift+Y`, type:

```text
std::_Func_base<char const *> *
```

The prototype is rewritten and the pseudocode refreshes:

```c
__int64 __fastcall consume(std::_Func_base<char const *> *a1)
```

## Notes and limits

- **It only resolves types that already exist.** This is a lookup by name, not a
  declaration parser, so it cannot invent a type. Import the PDB (or otherwise
  create the type) first — that is exactly the situation it targets.
- **Changing a member's size re-lays-out the struct.** Later members shift, as they
  would with any type change. The plugin warns about this in the log; check the
  layout in the Structures window (`Shift+F1`) if offsets matter.
- **Struct/union members only, not function members** of a struct in the Local Types
  window.
- Tested with **IDA Professional 9.4** (`hexrays 9.4.0.260714`). The `<>` lookup path
  is version-independent, but the argument/prototype behaviour is specific to 9.4+.

## Requirements

- IDA 7.6+ with the Hex-Rays decompiler (only the pseudocode path needs Hex-Rays;
  the Local Types and disassembly paths work without it).

## License

MIT — see [LICENSE](LICENSE).
