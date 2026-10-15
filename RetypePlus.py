"""RetypePlus - apply types that IDA's own "Set type" (Y) cannot handle.

Problem
-------
Types imported from a PDB often carry C++ template names such as:

    std::_Func_base<char const *>

They live in the local type library and are perfectly usable, but IDA's
declaration parser rejects "<" and ">" inside a type name. So the built-in
"Set type" (Y) dialog cannot resolve them, and the type cannot be applied
from the UI at all.

This plugin resolves types with tinfo_t.get_named_type() instead of parsing
a declaration, so those names work. It behaves like Y, but accepts anything
that already exists in the type library.

Also fixes three IDA 9.4 retyping problems
-----------------------------------------
1. Retyping a function argument used to go through vdui_t.set_lvar_type().
   IDA 9.4 refuses that for arguments with:

       Sorry, cannot change argument type.
       Please edit the function prototype instead

   The plugin now rewrites the function prototype instead
   (tinfo_t.set_funcarg_type() + apply_tinfo()), as IDA demands.

2. Retyping a local variable could fail with:

       Sorry, cannot change variable type

   vdui_t.set_lvar_type() returns false whenever the new type does not fit
   the variable's register or stack slot. The plugin falls back to the
   persistent modify_user_lvar_info(MLI_TYPE) path, which lets the
   decompiler re-lay-out, and then verifies the change actually landed.

3. Retyping a struct member used to mutate a throwaway in-memory copy of
   the tinfo_t, so nothing was ever saved. The plugin now rebuilds the
   struct and writes it back to the TIL.

Usage
-----
Ctrl+Shift+Y, or Edit/Plugins/Apply Named Type.

  - In a pseudocode window: put the cursor on a variable or expression.
  - In the Local Types window: put the cursor on a struct/union member.
  - In the disassembly listing: put the cursor on the address.

Then type the type name, for example:

    std::_Func_base<char const *> *

Tested with IDA Professional 9.4 (hexrays 9.4.0.260714).
"""

import ida_idaapi
import ida_kernwin
import ida_typeinf
import ida_hexrays
import ida_bytes
import ida_funcs
import ida_nalt

ACTION_NAME = "apply_named_type_action"

# ------------------------------------------------------------
# 工具函数：按名获取类型（绕开 parse_decl，支持 <> 等 IDA 认为非法的名字）
# ------------------------------------------------------------
def get_named_tinfo(type_str):
    full_str = type_str.strip()
    if not full_str:
        return None, None, 0, ""

    # 分离指针层级
    type_str = full_str
    ptr_level = 0
    while type_str.endswith("*"):
        ptr_level += 1
        type_str = type_str[:-1].strip()

    ti = ida_typeinf.get_idati()

    base_tif = ida_typeinf.tinfo_t()
    if not base_tif.get_named_type(ti, type_str):
        # 类型库里没有这个名字：Builtin（int/char/void…）、数组、复合声明。
        # 直接拿完整声明去 parse（'void *' 这种基类型本身无法单独 parse）。
        if not base_tif.parse(full_str, ti):
            return None, None, 0, ""
        display = base_tif.dstr()
        return base_tif, display, ptr_level, display

    canonical_name = base_tif.get_type_name()

    tif = base_tif
    for _ in range(ptr_level):
        ptr_tif = ida_typeinf.tinfo_t()
        if not ptr_tif.create_ptr(tif):
            return None, None, 0, ""
        tif = ptr_tif

    display_name = canonical_name + " *" * ptr_level if ptr_level > 0 else canonical_name
    return tif, canonical_name, ptr_level, display_name


# ------------------------------------------------------------
# 工具函数：拿到伪代码窗口所显示函数的“当前”原型
# IDA 9.4 起，改参数类型必须走函数原型，不能直接改 lvar
# ------------------------------------------------------------
def get_current_prototype(vu, func_ea):
    proto = ida_typeinf.tinfo_t()

    # 首选：cfunc_t 里的原型（与伪代码窗口里显示的一致）
    try:
        if vu is not None and vu.valid():
            cf = vu.cfunc
            if cf is not None and cf.get_func_type(proto) and not proto.empty():
                return proto
    except Exception:
        pass

    # 次选：数据库/函数记录里的原型
    try:
        if func_ea != ida_idaapi.BADADDR and ida_nalt.get_tinfo(proto, func_ea) and not proto.empty():
            return proto
    except Exception:
        pass

    try:
        fn = ida_funcs.get_func(func_ea)
        if fn is not None:
            p = fn.prototype
            if p is not None and not p.empty():
                return p
    except Exception:
        pass

    # 最后手段：现反编译一次，从 cfunc_t 取（IDA 9.x 里 nalt/func_t 常见为空）
    try:
        cf = ida_hexrays.decompile(func_ea)
        if cf is not None and cf.get_func_type(proto) and not proto.empty():
            return proto
    except Exception:
        pass

    return None


def is_arg_lvar(lvar):
    """lvar 是不是函数参数。不同版本 is_arg_var 有的是属性有的是方法。"""
    try:
        v = lvar.is_arg_var
        if callable(v):
            v = v()
        return bool(v)
    except Exception:
        try:
            return not lvar.is_notarg()
        except Exception:
            return False


def tif_is_usable(tif):
    """新类型必须是有效的 tinfo_t；否则底层 SWIG 会抛 null reference。"""
    if tif is None:
        return False
    try:
        return not tif.empty()
    except Exception:
        return False


def errstr(rc):
    try:
        if isinstance(rc, int):
            return ida_typeinf.tinfo_errstr(rc)
    except Exception:
        pass
    return str(rc)


# ------------------------------------------------------------
# 场景 A：把类型应用到“函数参数”上
# 9.4 不允许 lvar_t.set_lvar_type() 改参数类型（会弹
# "Sorry, cannot change argument type."），必须重建原型。
# ------------------------------------------------------------
def apply_to_funcarg(vu, func_ea, arg_index, new_tif, display_name):
    if not tif_is_usable(new_tif):
        return False, "invalid (empty) target type"

    proto = get_current_prototype(vu, func_ea)
    if proto is None:
        return False, "cannot get the current function prototype"

    # 已经是这个类型了：直接算成功，免得重复应用时报错
    try:
        cur = proto.get_nth_arg(arg_index)
        if not cur.empty() and cur == new_tif:
            return True, display_name
    except Exception:
        pass

    patched = proto.copy()
    rc = patched.set_funcarg_type(arg_index, new_tif, 0)
    if int(rc) != ida_typeinf.TERR_OK:
        return False, "set_funcarg_type failed: %s" % errstr(rc)

    ok = ida_typeinf.apply_tinfo(func_ea, patched, ida_typeinf.TINFO_DEFINITE)
    if not ok:
        return False, "apply_tinfo failed (new prototype was rejected)"

    # 让反编译缓存失效，否则伪代码窗口还显示老类型
    try:
        ida_hexrays.mark_cfunc_dirty(func_ea, False)
    except Exception:
        pass

    return True, display_name


# ------------------------------------------------------------
# 场景 B：把类型应用到“局部变量”上
# 无脑调 vdui_t.set_lvar_type() 在 9.4 会失败并弹
# "Sorry, cannot change variable type"（例如寄存器局部变量、
# 或者新类型在当前栈槽/寄存器里放不下）。失败时改用持久化的
# modify_user_lvar_info(MLI_TYPE)，它能让反编译器重新布局。
# 返回 (ok, message)；ok=True 时类型已经生效并落库。
# ------------------------------------------------------------
def apply_to_lvar(vu, func_ea, lvar, new_tif, display_name):
    """返回值 (ok, message)。ok=True 时调用方还需要 vu.refresh_view(True)。

    注意：这里绝对不能调用 mark_cfunc_dirty()。它会连同 vdui 的
    cfunc 一起失效，之后调用方再 refresh_view() 会让 IDA 直接崩溃
    （实测 exit 139）。让 refresh_view(True) 自己重新反编译即可。
    """
    if not tif_is_usable(new_tif):
        return False, "invalid (empty) target type"

    name = lvar.name or "?"

    # 1) 首选：vdui 路径（和 Y 键一致）。成功时视图仍然有效，
    #    直接比对内存里的 lvar.tif 就能确认。
    try:
        if vu.set_lvar_type(lvar, new_tif) and lvar_type_matches(lvar, new_tif):
            return True, name
    except Exception:
        pass

    # 2) 兜底：持久化用户变量信息，让反编译器重新布局。
    #    对寄存器局部变量等放不下的情况，底层会返回 True 却什么都不改，
    #    因此必须靠“目标类型出现次数变多”来判定，不能信返回值。
    before = count_lvars_with_type(func_ea, new_tif)
    try:
        mli = ida_hexrays.lvar_saved_info_t()
        mli.ll = lvar
        mli.type = new_tif
        mli.size = -1
        mli.name = lvar.name
        rc = ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, mli)
    except Exception as e:
        return False, "modify_user_lvar_info raised %r" % (e,)

    if not rc:
        return False, "cannot change type of %s (modify_user_lvar_info failed)" % name

    if count_lvars_with_type(func_ea, new_tif) > before:
        return True, name

    # 真的没改成；把这次无效的用户信息撤掉，免得留脏数据
    try:
        mli.type = lvar.tif
        ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, mli)
    except Exception:
        pass
    return False, ("cannot change type of %s; the variable cannot hold %s "
                   "(register/stack slot too small)" % (name, display_name))


def lvar_type_matches(lvar, new_tif):
    """当前 lvar 的类型是否已经是目标类型。"""
    try:
        return lvar.tif == new_tif
    except Exception:
        try:
            return lvar.tif.dstr() == new_tif.dstr()
        except Exception:
            return False


def count_lvars_with_type(func_ea, tif):
    """函数局部变量里，当前类型等于 tif 的个数。

    改名（v4 -> var8 之类）之后按名字找已经不准了，用计数更可靠。
    """
    n = 0
    try:
        cf = ida_hexrays.decompile(func_ea)
        if cf is None:
            return 0
        for i in range(len(cf.lvars)):
            if lvar_type_matches(cf.lvars[i], tif):
                n += 1
    except Exception:
        return 0
    return n


# ------------------------------------------------------------
# 伪代码窗口：改光标处的变量/表达式类型（同 Y 键）
# ------------------------------------------------------------
def apply_in_pseudocode(type_name):
    widget = ida_kernwin.get_current_viewer()
    vu = ida_hexrays.get_widget_vdui(widget)
    if not vu:
        return False

    item = vu.item
    if not item:
        return False

    tif, canonical_name, ptr_level, display_name = get_named_tinfo(type_name)
    if not tif:
        ida_kernwin.msg(f"[!] Type not found: {type_name}\n")
        return True

    # 先确认这个函数是不是参数被改了类型，需要走原型
    func_ea = ida_idaapi.BADADDR
    try:
        func_ea = vu.cfunc.entry_ea
    except Exception:
        pass

    if item.citype == ida_hexrays.VDI_LVAR:
        lvar = item.get_lvar()
        if not lvar:
            ida_kernwin.msg("[*] Pseudocode: no variable at cursor\n")
            return True

        # 参数：必须改原型（IDA 9.4 起 lvar 级别的改动会失败）
        if is_arg_lvar(lvar):
            arg_index = get_arg_index(vu, lvar)
            if arg_index < 0:
                ida_kernwin.msg(f"[!] Cannot locate argument '{lvar.name}' in the prototype\n")
                return True
            ok, info = apply_to_funcarg(vu, func_ea, arg_index, tif, display_name)
            if not ok:
                ida_kernwin.msg(f"[!] {info}\n")
                return True
            ida_kernwin.msg(f"[+] argument {lvar.name} (proto arg #{arg_index}) : {display_name}\n")
            vu.refresh_view(True)
            return True

        # 普通局部变量
        ok, info = apply_to_lvar(vu, func_ea, lvar, tif, display_name)
        if ok:
            vu.refresh_view(True)
            ida_kernwin.msg(f"[+] {lvar.name} : {display_name}\n")
        else:
            ida_kernwin.msg(f"[!] {info}\n")
        return True

    if item.citype == ida_hexrays.VDI_EXPR:
        if item.e:
            if item.e.op == ida_hexrays.cot_obj:
                ea = item.e.obj_ea
                ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
                vu.refresh_view(True)
                ida_kernwin.msg(f"[+] Global at {hex(ea)} : {display_name}\n")
                return True
            elif item.e.op == ida_hexrays.cot_var:
                lvar = item.get_lvar()
                if not lvar:
                    ida_kernwin.msg("[*] Pseudocode: no variable at cursor\n")
                    return True

                if is_arg_lvar(lvar):
                    arg_index = get_arg_index(vu, lvar)
                    if arg_index < 0:
                        ida_kernwin.msg(f"[!] Cannot locate argument '{lvar.name}' in the prototype\n")
                        return True
                    ok, info = apply_to_funcarg(vu, func_ea, arg_index, tif, display_name)
                    if not ok:
                        ida_kernwin.msg(f"[!] {info}\n")
                        return True
                    ida_kernwin.msg(f"[+] argument {lvar.name} (proto arg #{arg_index}) : {display_name}\n")
                    vu.refresh_view(True)
                    return True

                ok, info = apply_to_lvar(vu, func_ea, lvar, tif, display_name)
                if ok:
                    vu.refresh_view(True)
                    ida_kernwin.msg(f"[+] {lvar.name} : {display_name}\n")
                else:
                    ida_kernwin.msg(f"[!] {info}\n")
                return True

    ida_kernwin.msg("[*] Pseudocode: not on a variable/expression\n")
    return False


def get_arg_index(vu, lvar):
    """把 lvar 映射到函数原型里的参数序号（0 基）。返回 -1 表示失败。"""
    try:
        cf = vu.cfunc
        for pos, var_idx in enumerate(cf.argidx):
            if cf.lvars[var_idx] == lvar:
                return pos
    except Exception:
        pass
    return -1


# ------------------------------------------------------------
# 工具函数：重建 struct/union 并更新指定成员的类型
# tinfo_t::set_udm_type() 的改动只留在内存副本里；若是变长类型还会
# TERR_OVERLAP 或被 ETF_MAY_DESTROY 把后续成员删掉，所以走重建。
# ------------------------------------------------------------
def rebuild_member_type(struct_name, member_idx, new_tif):
    if not tif_is_usable(new_tif):
        return False, "invalid (empty) target type"

    til = ida_typeinf.get_idati()

    st = ida_typeinf.tinfo_t()
    if not st.get_named_type(til, struct_name):
        return False, "Type '%s' not found" % struct_name

    udt = ida_typeinf.udt_type_data_t()
    if not st.get_udt_details(udt):
        return False, "Cannot get members of '%s'" % struct_name
    if member_idx >= len(udt):
        return False, "Member index %d out of range" % member_idx

    udt[member_idx].type = new_tif

    rebuilt = ida_typeinf.tinfo_t()
    if not rebuilt.create_udt(udt):
        return False, "create_udt failed (type may be invalid here)"

    rc = rebuilt.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
    if int(rc) != ida_typeinf.TERR_OK:
        return False, "Failed to save '%s': %s" % (struct_name, errstr(rc))

    return True, struct_name


# ------------------------------------------------------------
# Local Types 窗口：改 struct 成员类型（点击哪里改哪里）
# 通过 action ctx.type_ref 获取当前光标处的类型/成员引用（官方 API）
# ------------------------------------------------------------
def apply_in_type_editor(ctx, type_name):
    type_name = type_name.strip()

    tref = None
    if ctx and ctx.has_flag(ida_kernwin.ACF_HAS_TYPE_REF) and ctx.type_ref:
        tref = ctx.type_ref
    if tref is None:
        # 兜底：从光标位置解析（get_custom_viewer_location 链）
        try:
            import ida_moves
            w = ida_kernwin.get_current_widget()
            loc = ida_moves.lochist_entry_t()
            if w and ida_kernwin.get_custom_viewer_location(loc, w):
                p = loc.place()
                ti = ida_kernwin.place_t.as_tiplace_t(p)
                if ti:
                    t2 = ida_typeinf.til_type_ref_t()
                    if ti.fill_type_ref(t2, None):
                        tref = t2
        except Exception as e:
            ida_kernwin.msg(f"[*] location fallback failed: {e!r}\n")

    if tref is None:
        ida_kernwin.msg("[!] Cannot get current type reference. Click a member first.\n")
        return True

    t_target, canonical_name, ptr_level, display_name = get_named_tinfo(type_name)
    if not t_target:
        ida_kernwin.msg(f"[!] Target type not found: {type_name}\n")
        return True

    # 场景1：光标在 struct/union 成员上
    if tref.on_member() and tref.udm and tref.tif.is_correct():
        member_name = tref.udm.name
        struct_name = tref.tif.get_type_name() or ''
        member_idx = tref.memidx
        ida_kernwin.msg(f"[*] Member '{member_name}' of {struct_name} (index {member_idx})\n")

        if member_idx is None or member_idx < 0:
            ida_kernwin.msg("[!] Invalid member index\n")
            return True
        if not struct_name:
            ida_kernwin.msg("[!] Anonymous type: cannot write the change back\n")
            return True

        # set_udm_type() 只在内存副本上生效（而且对变长类型会 TERR_OVERLAP 或删掉后续成员），
        # 必须重建整个 udt 再 set_named_type() 写回 TIL 才算真的改掉。
        ok, info = rebuild_member_type(struct_name, member_idx, t_target)
        if not ok:
            ida_kernwin.msg(f"[!] {info}\n")
            return True

        ida_kernwin.msg(f"[+] {struct_name}::{member_name} -> {display_name}\n")
        ida_kernwin.msg("[*] Note: 类型长度变化会重排后续成员偏移，请核对布局\n")
        return True

    # 场景2：光标在类型行（无成员）——提示需要选中成员
    tname = tref.tif.get_type_name() if tref.tif.is_correct() else ''
    ida_kernwin.msg(f"[!] Cursor on type '{tname}' (not a member). Click a member to change its type.\n")
    return True


# ------------------------------------------------------------
# 反汇编/其他窗口：应用类型到当前地址（同 Y 键）
# ------------------------------------------------------------
def apply_in_disasm(type_name):
    ea = ida_kernwin.get_screen_ea()
    if ea == ida_idaapi.BADADDR:
        ida_kernwin.msg("[!] No address at cursor\n")
        return

    tif, canonical_name, ptr_level, display_name = get_named_tinfo(type_name)
    if not tif:
        ida_kernwin.msg(f"[!] Type not found: {type_name}\n")
        return

    ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
    if ok:
        ida_kernwin.msg(f"[+] {hex(ea)} : {display_name}\n")
    else:
        ida_kernwin.msg("[!] Failed to apply type (address may have existing type)\n")


# ------------------------------------------------------------
# Action Handler
# ------------------------------------------------------------
class ApplyNamedTypeHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        # 检测当前窗口
        widget = ida_kernwin.get_current_viewer()
        wtype = None
        wtitle = ''
        if widget:
            wtype = ida_kernwin.get_widget_type(widget)
            wtitle = ida_kernwin.get_widget_title(widget) or ''

        is_local_types = (wtitle.startswith('Local Types')
                          or wtype in (ida_kernwin.BWN_LOCTYPS, ida_kernwin.BWN_TYPE_EDITOR, 58))
        is_pseudocode = (wtype == ida_kernwin.BWN_PSEUDOCODE
                         or (widget and ida_hexrays.get_widget_vdui(widget) is not None))

        # Local Types：先输入类型名，再应用到光标处成员（点击哪里改哪里）
        if is_local_types:
            type_name = ida_kernwin.ask_str("", 0, "Enter type name")
            if not type_name:
                return 1
            apply_in_type_editor(ctx, type_name)
            return 1

        # 伪代码/反汇编/其他：输入类型名后应用
        type_name = ida_kernwin.ask_str("", 0, "Enter type name")
        if not type_name:
            return 1

        if is_pseudocode:
            if apply_in_pseudocode(type_name):
                return 1

        apply_in_disasm(type_name)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# ------------------------------------------------------------
# 插件主体
# ------------------------------------------------------------
class ApplyNamedTypePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Apply named type anywhere (Y-key replacement, PDB safe)"
    help = ""
    wanted_name = "Apply Named Type (Ctrl+Shift+Y)"
    wanted_hotkey = ""

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("[!] Hex-Rays not available\n")

        action_desc = ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Apply Named Type",
            ApplyNamedTypeHandler(),
            "Ctrl+Shift+Y",
            "Apply named type to current item (like Y, but accepts <> names)",
            0
        )

        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/",
            ACTION_NAME,
            ida_kernwin.SETMENU_APP
        )
        ida_kernwin.msg("[+] ApplyNamedType loaded (Ctrl+Shift+Y)\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ApplyNamedTypePlugin()