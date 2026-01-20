#include "vm.h"
#include "papagaio.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t native_argc(VM *vm, List *global)
{
    if (vm && vm->argc_entry && urb_obj_type(vm->argc_entry->obj) == URB_T_NUMBER &&
        vm->argc_entry->obj->size >= 3) {
        return (uint32_t)vm->argc_entry->obj->data[2].f;
    }
    ObjEntry *argc_entry = vm_global_find_by_key(global, "__argc");
    if (!argc_entry || urb_obj_type(argc_entry->obj) != URB_T_NUMBER || argc_entry->obj->size < 3) {
        return 0;
    }
    return (uint32_t)argc_entry->obj->data[2].f;
}

static ObjEntry *native_arg(List *stack, uint32_t argc, uint32_t idx)
{
    if (!stack || idx >= argc) return NULL;
    Int base = stack->size - (Int)argc;
    if (base < 2) return NULL;
    Int pos = base + (Int)idx;
    if (pos < 2 || pos >= stack->size) return NULL;
    return (ObjEntry*)stack->data[pos].p;
}

static ObjEntry *native_this(VM *vm)
{
    if (!vm || !vm->this_entry || !vm->this_entry->in_use) return NULL;
    return vm->this_entry;
}

static ObjEntry *native_target(VM *vm, List *stack, uint32_t argc)
{
    ObjEntry *self = native_this(vm);
    if (self) {
        Int type = urb_obj_type(self->obj);
        if (type == URB_T_OBJECT || type == URB_T_NUMBER || type == URB_T_CHAR || type == URB_T_BYTE) {
            return self;
        }
    }
    return native_arg(stack, argc, 0);
}

static int entry_as_number(ObjEntry *entry, Float *out)
{
    if (!entry || urb_obj_type(entry->obj) != URB_T_NUMBER || entry->obj->size < 3) return 0;
    *out = entry->obj->data[2].f;
    return 1;
}

static int entry_as_string(ObjEntry *entry, const char **out, size_t *len)
{
    if (!entry) return 0;
    Int type = urb_obj_type(entry->obj);
    if (type != URB_T_CHAR && type != URB_T_BYTE) return 0;
    *out = urb_char_data(entry->obj);
    *len = urb_char_len(entry->obj);
    return 1;
}

static void push_number(VM *vm, List *stack, Float value)
{
    urb_object_add(stack, vm_make_number_value(vm, value));
}

static void push_string(VM *vm, List *stack, const char *s, size_t len)
{
    urb_object_add(stack, vm_make_char_value(vm, s, len));
}

static int number_to_int(ObjEntry *entry, Int *out);

static ObjEntry *object_find_by_key_len(List *obj, const char *name, size_t len)
{
    if (!obj || urb_obj_type(obj) != URB_T_OBJECT) return NULL;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        if (!entry) continue;
        ObjEntry *key = urb_obj_key(entry->obj);
        if (!key || urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_len(key->obj) == len &&
            memcmp(urb_char_data(key->obj), name, len) == 0) {
            return entry;
        }
    }
    return NULL;
}

static ObjEntry *object_find_by_key(List *obj, const char *name)
{
    return object_find_by_key_len(obj, name, strlen(name));
}

static int entry_as_u32(ObjEntry *entry, uint32_t *out)
{
    Int iv = 0;
    if (!entry || urb_obj_type(entry->obj) != URB_T_NUMBER || entry->obj->size < 3) return 0;
    if (!number_to_int(entry, &iv)) return 0;
    if (iv < 0 || (UInt)iv > 0xFFFFFFFFu) return 0;
    *out = (uint32_t)iv;
    return 1;
}

static int entry_as_u8(ObjEntry *entry, uint8_t *out)
{
    uint32_t v = 0;
    if (!entry_as_u32(entry, &v) || v > 255) return 0;
    *out = (uint8_t)v;
    return 1;
}

static void ast_err(char *err, size_t cap, const char *msg)
{
    if (!err || cap == 0) return;
    snprintf(err, cap, "%s", msg);
}

static int ast_to_bytecode(VM *vm, ObjEntry *ast, Bytecode *out, char *err, size_t err_cap)
{
    if (!vm || !ast || !out) {
        ast_err(err, err_cap, "emit expects an AST object");
        return 0;
    }
    if (urb_obj_type(ast->obj) != URB_T_OBJECT) {
        ast_err(err, err_cap, "emit expects an AST object");
        return 0;
    }

    ObjEntry *type_entry = object_find_by_key(ast->obj, "type");
    if (type_entry) {
        const char *type = NULL;
        size_t type_len = 0;
        if (!entry_as_string(type_entry, &type, &type_len) ||
            type_len != 8 || memcmp(type, "bytecode", 8) != 0) {
            ast_err(err, err_cap, "emit expects bytecode AST");
            return 0;
        }
    }

    ObjEntry *ops_entry = object_find_by_key(ast->obj, "ops");
    if (!ops_entry || urb_obj_type(ops_entry->obj) != URB_T_OBJECT) {
        ast_err(err, err_cap, "emit expects ops array");
        return 0;
    }

    bc_init(out);

    List *ops = ops_entry->obj;
    for (Int i = 2; i < ops->size; i++) {
        ObjEntry *op_entry = (ObjEntry*)ops->data[i].p;
        if (!op_entry || urb_obj_type(op_entry->obj) != URB_T_OBJECT) {
            ast_err(err, err_cap, "emit expects op objects");
            bc_free(out);
            return 0;
        }
        ObjEntry *op_name_entry = object_find_by_key(op_entry->obj, "op");
        const char *op_name = NULL;
        size_t op_len = 0;
        if (!op_name_entry || !entry_as_string(op_name_entry, &op_name, &op_len)) {
            ast_err(err, err_cap, "emit expects op name");
            bc_free(out);
            return 0;
        }

        if (op_len == 8 && memcmp(op_name, "PUSH_NUM", 8) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            if (!val || urb_obj_type(val->obj) != URB_T_NUMBER || val->obj->size < 3) {
                ast_err(err, err_cap, "PUSH_NUM expects value");
                bc_free(out);
                return 0;
            }
            double v = (double)val->obj->data[2].f;
            if (!bc_emit_u8(out, BC_PUSH_NUM) || !bc_emit_f64(out, v)) {
                ast_err(err, err_cap, "failed to emit PUSH_NUM");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 9 && memcmp(op_name, "PUSH_CHAR", 9) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen) || slen != 1) {
                ast_err(err, err_cap, "PUSH_CHAR expects single character");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_CHAR) || !bc_emit_string(out, s, slen)) {
                ast_err(err, err_cap, "failed to emit PUSH_CHAR");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 11 && memcmp(op_name, "PUSH_STRING", 11) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen)) {
                ast_err(err, err_cap, "PUSH_STRING expects value");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_STRING) || !bc_emit_string(out, s, slen)) {
                ast_err(err, err_cap, "failed to emit PUSH_STRING");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 9 && memcmp(op_name, "PUSH_BYTE", 9) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            uint8_t v = 0;
            if (!val || !entry_as_u8(val, &v)) {
                ast_err(err, err_cap, "PUSH_BYTE expects 0-255");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_BYTE) || !bc_emit_u8(out, v)) {
                ast_err(err, err_cap, "failed to emit PUSH_BYTE");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 12 && memcmp(op_name, "BUILD_NUMBER", 12) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_NUMBER expects count");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_NUMBER) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_NUMBER");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 10 && memcmp(op_name, "BUILD_BYTE", 10) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_BYTE expects count");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_BYTE) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_BYTE");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 12 && memcmp(op_name, "BUILD_OBJECT", 12) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_OBJECT expects count");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_OBJECT) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_OBJECT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 16 && memcmp(op_name, "BUILD_NUMBER_LIT", 16) == 0) {
            ObjEntry *values_entry = object_find_by_key(op_entry->obj, "values");
            if (!values_entry || urb_obj_type(values_entry->obj) != URB_T_OBJECT) {
                ast_err(err, err_cap, "BUILD_NUMBER_LIT expects values");
                bc_free(out);
                return 0;
            }
            List *vals = values_entry->obj;
            uint32_t count = (uint32_t)(vals->size - 2);
            if (!bc_emit_u8(out, BC_BUILD_NUMBER_LIT) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_NUMBER_LIT");
                bc_free(out);
                return 0;
            }
            for (Int j = 2; j < vals->size; j++) {
                ObjEntry *v = (ObjEntry*)vals->data[j].p;
                if (!v || urb_obj_type(v->obj) != URB_T_NUMBER || v->obj->size < 3) {
                    ast_err(err, err_cap, "BUILD_NUMBER_LIT values must be numbers");
                    bc_free(out);
                    return 0;
                }
                if (!bc_emit_f64(out, (double)v->obj->data[2].f)) {
                    ast_err(err, err_cap, "failed to emit BUILD_NUMBER_LIT value");
                    bc_free(out);
                    return 0;
                }
            }
        } else if (op_len == 13 && memcmp(op_name, "BUILD_FUNCTION", 13) == 0) {
            ObjEntry *argc_entry = object_find_by_key(op_entry->obj, "argc");
            ObjEntry *vararg_entry = object_find_by_key(op_entry->obj, "vararg");
            ObjEntry *code_entry = object_find_by_key(op_entry->obj, "code");
            ObjEntry *args_entry = object_find_by_key(op_entry->obj, "args");
            uint32_t argc = 0;
            uint32_t vararg = 0;
            if (!argc_entry || !vararg_entry || !code_entry || !args_entry ||
                !entry_as_u32(argc_entry, &argc) || !entry_as_u32(vararg_entry, &vararg)) {
                ast_err(err, err_cap, "BUILD_FUNCTION expects argc, vararg, code, args");
                bc_free(out);
                return 0;
            }
            const char *code = NULL;
            size_t code_len = 0;
            if (!entry_as_string(code_entry, &code, &code_len)) {
                ast_err(err, err_cap, "BUILD_FUNCTION expects code bytes");
                bc_free(out);
                return 0;
            }
            if (code_len > 0xFFFFFFFFu) {
                ast_err(err, err_cap, "BUILD_FUNCTION code too large");
                bc_free(out);
                return 0;
            }
            if (urb_obj_type(args_entry->obj) != URB_T_OBJECT) {
                ast_err(err, err_cap, "BUILD_FUNCTION expects args array");
                bc_free(out);
                return 0;
            }
            List *args = args_entry->obj;
            if ((uint32_t)(args->size - 2) < argc) {
                ast_err(err, err_cap, "BUILD_FUNCTION args count mismatch");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_FUNCTION) ||
                !bc_emit_u32(out, argc) ||
                !bc_emit_u32(out, vararg) ||
                !bc_emit_u32(out, (uint32_t)code_len) ||
                !bc_emit_bytes(out, (const unsigned char*)code, code_len)) {
                ast_err(err, err_cap, "failed to emit BUILD_FUNCTION");
                bc_free(out);
                return 0;
            }
            for (uint32_t j = 0; j < argc; j++) {
                ObjEntry *arg = (ObjEntry*)args->data[2 + j].p;
                if (!arg || urb_obj_type(arg->obj) != URB_T_OBJECT) {
                    ast_err(err, err_cap, "BUILD_FUNCTION arg must be object");
                    bc_free(out);
                    return 0;
                }
                ObjEntry *name_entry = object_find_by_key(arg->obj, "name");
                const char *name = NULL;
                size_t name_len = 0;
                if (!name_entry || !entry_as_string(name_entry, &name, &name_len)) {
                    ast_err(err, err_cap, "BUILD_FUNCTION arg expects name");
                    bc_free(out);
                    return 0;
                }
                ObjEntry *def_entry = object_find_by_key(arg->obj, "default");
                const char *def = NULL;
                size_t def_len = 0;
                if (def_entry && urb_obj_type(def_entry->obj) != URB_T_NULL) {
                    if (!entry_as_string(def_entry, &def, &def_len)) {
                        ast_err(err, err_cap, "BUILD_FUNCTION default must be bytes");
                        bc_free(out);
                        return 0;
                    }
                }
                if (def_len > 0xFFFFFFFFu) {
                    ast_err(err, err_cap, "BUILD_FUNCTION default too large");
                    bc_free(out);
                    return 0;
                }
                if (!bc_emit_string(out, name, name_len) ||
                    !bc_emit_u32(out, (uint32_t)def_len)) {
                    ast_err(err, err_cap, "failed to emit BUILD_FUNCTION arg");
                    bc_free(out);
                    return 0;
                }
                if (def_len > 0) {
                    if (!bc_emit_bytes(out, (const unsigned char*)def, def_len)) {
                        ast_err(err, err_cap, "failed to emit BUILD_FUNCTION default");
                        bc_free(out);
                        return 0;
                    }
                }
            }
        } else if (op_len == 11 && memcmp(op_name, "LOAD_GLOBAL", 11) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            const char *name = NULL;
            size_t name_len = 0;
            if (!name_entry || !entry_as_string(name_entry, &name, &name_len)) {
                ast_err(err, err_cap, "LOAD_GLOBAL expects name");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_LOAD_GLOBAL) || !bc_emit_string(out, name, name_len)) {
                ast_err(err, err_cap, "failed to emit LOAD_GLOBAL");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 12 && memcmp(op_name, "STORE_GLOBAL", 12) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            const char *name = NULL;
            size_t name_len = 0;
            if (!name_entry || !entry_as_string(name_entry, &name, &name_len)) {
                ast_err(err, err_cap, "STORE_GLOBAL expects name");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_STORE_GLOBAL) || !bc_emit_string(out, name, name_len)) {
                ast_err(err, err_cap, "failed to emit STORE_GLOBAL");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 4 && memcmp(op_name, "CALL", 4) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            ObjEntry *argc_entry = object_find_by_key(op_entry->obj, "argc");
            const char *name = NULL;
            size_t name_len = 0;
            uint32_t argc = 0;
            if (!name_entry || !argc_entry ||
                !entry_as_string(name_entry, &name, &name_len) ||
                !entry_as_u32(argc_entry, &argc)) {
                ast_err(err, err_cap, "CALL expects name and argc");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_CALL) ||
                !bc_emit_string(out, name, name_len) ||
                !bc_emit_u32(out, argc)) {
                ast_err(err, err_cap, "failed to emit CALL");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "JMP", 3) == 0) {
            ObjEntry *target_entry = object_find_by_key(op_entry->obj, "target");
            uint32_t target = 0;
            if (!target_entry || !entry_as_u32(target_entry, &target)) {
                ast_err(err, err_cap, "JMP expects target");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_JMP) || !bc_emit_u32(out, target)) {
                ast_err(err, err_cap, "failed to emit JMP");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 12 && memcmp(op_name, "JMP_IF_FALSE", 12) == 0) {
            ObjEntry *target_entry = object_find_by_key(op_entry->obj, "target");
            uint32_t target = 0;
            if (!target_entry || !entry_as_u32(target_entry, &target)) {
                ast_err(err, err_cap, "JMP_IF_FALSE expects target");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_JMP_IF_FALSE) || !bc_emit_u32(out, target)) {
                ast_err(err, err_cap, "failed to emit JMP_IF_FALSE");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 8 && memcmp(op_name, "LOAD_ROOT", 8) == 0) {
            if (!bc_emit_u8(out, BC_LOAD_ROOT)) {
                ast_err(err, err_cap, "failed to emit LOAD_ROOT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 9 && memcmp(op_name, "LOAD_THIS", 9) == 0) {
            if (!bc_emit_u8(out, BC_LOAD_THIS)) {
                ast_err(err, err_cap, "failed to emit LOAD_THIS");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 8 && memcmp(op_name, "SET_THIS", 8) == 0) {
            if (!bc_emit_u8(out, BC_SET_THIS)) {
                ast_err(err, err_cap, "failed to emit SET_THIS");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 5 && memcmp(op_name, "INDEX", 5) == 0) {
            if (!bc_emit_u8(out, BC_INDEX)) {
                ast_err(err, err_cap, "failed to emit INDEX");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 11 && memcmp(op_name, "STORE_INDEX", 11) == 0) {
            if (!bc_emit_u8(out, BC_STORE_INDEX)) {
                ast_err(err, err_cap, "failed to emit STORE_INDEX");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 6 && memcmp(op_name, "RETURN", 6) == 0) {
            if (!bc_emit_u8(out, BC_RETURN)) {
                ast_err(err, err_cap, "failed to emit RETURN");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "POP", 3) == 0) {
            if (!bc_emit_u8(out, BC_POP)) {
                ast_err(err, err_cap, "failed to emit POP");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "DUP", 3) == 0) {
            if (!bc_emit_u8(out, BC_DUP)) {
                ast_err(err, err_cap, "failed to emit DUP");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 2 && memcmp(op_name, "GC", 2) == 0) {
            if (!bc_emit_u8(out, BC_GC)) {
                ast_err(err, err_cap, "failed to emit GC");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 4 && memcmp(op_name, "DUMP", 4) == 0) {
            if (!bc_emit_u8(out, BC_DUMP)) {
                ast_err(err, err_cap, "failed to emit DUMP");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "ADD", 3) == 0) {
            if (!bc_emit_u8(out, BC_ADD)) {
                ast_err(err, err_cap, "failed to emit ADD");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "SUB", 3) == 0) {
            if (!bc_emit_u8(out, BC_SUB)) {
                ast_err(err, err_cap, "failed to emit SUB");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "MUL", 3) == 0) {
            if (!bc_emit_u8(out, BC_MUL)) {
                ast_err(err, err_cap, "failed to emit MUL");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "DIV", 3) == 0) {
            if (!bc_emit_u8(out, BC_DIV)) {
                ast_err(err, err_cap, "failed to emit DIV");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "MOD", 3) == 0) {
            if (!bc_emit_u8(out, BC_MOD)) {
                ast_err(err, err_cap, "failed to emit MOD");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "NEG", 3) == 0) {
            if (!bc_emit_u8(out, BC_NEG)) {
                ast_err(err, err_cap, "failed to emit NEG");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "NOT", 3) == 0) {
            if (!bc_emit_u8(out, BC_NOT)) {
                ast_err(err, err_cap, "failed to emit NOT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 2 && memcmp(op_name, "EQ", 2) == 0) {
            if (!bc_emit_u8(out, BC_EQ)) {
                ast_err(err, err_cap, "failed to emit EQ");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "NEQ", 3) == 0) {
            if (!bc_emit_u8(out, BC_NEQ)) {
                ast_err(err, err_cap, "failed to emit NEQ");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 2 && memcmp(op_name, "LT", 2) == 0) {
            if (!bc_emit_u8(out, BC_LT)) {
                ast_err(err, err_cap, "failed to emit LT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "LTE", 3) == 0) {
            if (!bc_emit_u8(out, BC_LTE)) {
                ast_err(err, err_cap, "failed to emit LTE");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 2 && memcmp(op_name, "GT", 2) == 0) {
            if (!bc_emit_u8(out, BC_GT)) {
                ast_err(err, err_cap, "failed to emit GT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "GTE", 3) == 0) {
            if (!bc_emit_u8(out, BC_GTE)) {
                ast_err(err, err_cap, "failed to emit GTE");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "AND", 3) == 0) {
            if (!bc_emit_u8(out, BC_AND)) {
                ast_err(err, err_cap, "failed to emit AND");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 2 && memcmp(op_name, "OR", 2) == 0) {
            if (!bc_emit_u8(out, BC_OR)) {
                ast_err(err, err_cap, "failed to emit OR");
                bc_free(out);
                return 0;
            }
        } else {
            ast_err(err, err_cap, "unknown opcode in AST");
            bc_free(out);
            return 0;
        }
    }

    return 1;
}

static void sb_append_escaped(StrBuf *b, const char *s, size_t len, char quote)
{
    sb_append_char(b, quote);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '\n': sb_append_n(b, "\\n", 2); break;
        case '\r': sb_append_n(b, "\\r", 2); break;
        case '\t': sb_append_n(b, "\\t", 2); break;
        case '\\': sb_append_n(b, "\\\\", 2); break;
        case '"': sb_append_n(b, "\\\"", 2); break;
        case '\'': sb_append_n(b, "\\'", 2); break;
        default: sb_append_char(b, (char)c); break;
        }
    }
    sb_append_char(b, quote);
}

static int ast_to_source(VM *vm, ObjEntry *ast, StrBuf *out, char *err, size_t err_cap)
{
    if (!vm || !ast || urb_obj_type(ast->obj) != URB_T_OBJECT) {
        ast_err(err, err_cap, "ast_to_source expects AST object");
        return 0;
    }
    ObjEntry *ops_entry = object_find_by_key(ast->obj, "ops");
    if (!ops_entry || urb_obj_type(ops_entry->obj) != URB_T_OBJECT) {
        ast_err(err, err_cap, "ast_to_source expects ops array");
        return 0;
    }
    List *ops = ops_entry->obj;
    for (Int i = 2; i < ops->size; i++) {
        ObjEntry *op_entry = (ObjEntry*)ops->data[i].p;
        if (!op_entry || urb_obj_type(op_entry->obj) != URB_T_OBJECT) {
            ast_err(err, err_cap, "ast_to_source expects op objects");
            return 0;
        }
        ObjEntry *op_name_entry = object_find_by_key(op_entry->obj, "op");
        const char *op_name = NULL;
        size_t op_len = 0;
        if (!op_name_entry || !entry_as_string(op_name_entry, &op_name, &op_len)) {
            ast_err(err, err_cap, "ast_to_source expects op name");
            return 0;
        }
        sb_append_n(out, op_name, op_len);

        if (op_len == 8 && memcmp(op_name, "PUSH_NUM", 8) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            if (!val || urb_obj_type(val->obj) != URB_T_NUMBER || val->obj->size < 3) {
                ast_err(err, err_cap, "PUSH_NUM expects value");
                return 0;
            }
            char buf[64];
            snprintf(buf, sizeof(buf), " %.17g", (double)val->obj->data[2].f);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 9 && memcmp(op_name, "PUSH_CHAR", 9) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen) || slen != 1) {
                ast_err(err, err_cap, "PUSH_CHAR expects single character");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_escaped(out, s, slen, '\'');
        } else if (op_len == 11 && memcmp(op_name, "PUSH_STRING", 11) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen)) {
                ast_err(err, err_cap, "PUSH_STRING expects value");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_escaped(out, s, slen, '"');
        } else if (op_len == 9 && memcmp(op_name, "PUSH_BYTE", 9) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            uint32_t v = 0;
            if (!val || !entry_as_u32(val, &v)) {
                ast_err(err, err_cap, "PUSH_BYTE expects value");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)v);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 12 && memcmp(op_name, "BUILD_NUMBER", 12) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_NUMBER expects count");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)count);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 10 && memcmp(op_name, "BUILD_BYTE", 10) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_BYTE expects count");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)count);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 12 && memcmp(op_name, "BUILD_OBJECT", 12) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_OBJECT expects count");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)count);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 16 && memcmp(op_name, "BUILD_NUMBER_LIT", 16) == 0) {
            ObjEntry *values_entry = object_find_by_key(op_entry->obj, "values");
            if (!values_entry || urb_obj_type(values_entry->obj) != URB_T_OBJECT) {
                ast_err(err, err_cap, "BUILD_NUMBER_LIT expects values");
                return 0;
            }
            List *vals = values_entry->obj;
            uint32_t count = (uint32_t)(vals->size - 2);
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)count);
            sb_append_n(out, buf, strlen(buf));
            for (Int j = 2; j < vals->size; j++) {
                ObjEntry *v = (ObjEntry*)vals->data[j].p;
                if (!v || urb_obj_type(v->obj) != URB_T_NUMBER || v->obj->size < 3) {
                    ast_err(err, err_cap, "BUILD_NUMBER_LIT values must be numbers");
                    return 0;
                }
                char num_buf[64];
                snprintf(num_buf, sizeof(num_buf), " %.17g", (double)v->obj->data[2].f);
                sb_append_n(out, num_buf, strlen(num_buf));
            }
        } else if (op_len == 13 && memcmp(op_name, "BUILD_FUNCTION", 13) == 0) {
            ObjEntry *argc_entry = object_find_by_key(op_entry->obj, "argc");
            ObjEntry *vararg_entry = object_find_by_key(op_entry->obj, "vararg");
            ObjEntry *code_entry = object_find_by_key(op_entry->obj, "code");
            ObjEntry *args_entry = object_find_by_key(op_entry->obj, "args");
            uint32_t argc = 0;
            uint32_t vararg = 0;
            const char *code = NULL;
            size_t code_len = 0;
            if (!argc_entry || !vararg_entry || !code_entry || !args_entry ||
                !entry_as_u32(argc_entry, &argc) || !entry_as_u32(vararg_entry, &vararg) ||
                !entry_as_string(code_entry, &code, &code_len)) {
                ast_err(err, err_cap, "BUILD_FUNCTION expects argc, vararg, code, args");
                return 0;
            }
            char head[96];
            snprintf(head, sizeof(head), " %u %u %u", (unsigned)argc, (unsigned)vararg, (unsigned)code_len);
            sb_append_n(out, head, strlen(head));

            if (urb_obj_type(args_entry->obj) != URB_T_OBJECT) {
                ast_err(err, err_cap, "BUILD_FUNCTION expects args array");
                return 0;
            }
            List *args = args_entry->obj;
            for (uint32_t j = 0; j < argc; j++) {
                ObjEntry *arg = (ObjEntry*)args->data[2 + j].p;
                if (!arg || urb_obj_type(arg->obj) != URB_T_OBJECT) {
                    ast_err(err, err_cap, "BUILD_FUNCTION arg must be object");
                    return 0;
                }
                ObjEntry *name_entry = object_find_by_key(arg->obj, "name");
                const char *name = NULL;
                size_t name_len = 0;
                if (!name_entry || !entry_as_string(name_entry, &name, &name_len)) {
                    ast_err(err, err_cap, "BUILD_FUNCTION arg expects name");
                    return 0;
                }
                ObjEntry *def_entry = object_find_by_key(arg->obj, "default");
                size_t def_len = 0;
                if (def_entry && urb_obj_type(def_entry->obj) != URB_T_NULL) {
                    const char *def = NULL;
                    if (!entry_as_string(def_entry, &def, &def_len)) {
                        ast_err(err, err_cap, "BUILD_FUNCTION default must be bytes");
                        return 0;
                    }
                }
                sb_append_char(out, ' ');
                sb_append_n(out, name, name_len);
                char def_buf[32];
                snprintf(def_buf, sizeof(def_buf), " %u", (unsigned)def_len);
                sb_append_n(out, def_buf, strlen(def_buf));
            }
        } else if (op_len == 11 && memcmp(op_name, "LOAD_GLOBAL", 11) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            const char *name = NULL;
            size_t name_len = 0;
            if (!name_entry || !entry_as_string(name_entry, &name, &name_len)) {
                ast_err(err, err_cap, "LOAD_GLOBAL expects name");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_n(out, name, name_len);
        } else if (op_len == 12 && memcmp(op_name, "STORE_GLOBAL", 12) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            const char *name = NULL;
            size_t name_len = 0;
            if (!name_entry || !entry_as_string(name_entry, &name, &name_len)) {
                ast_err(err, err_cap, "STORE_GLOBAL expects name");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_n(out, name, name_len);
        } else if (op_len == 4 && memcmp(op_name, "CALL", 4) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            ObjEntry *argc_entry = object_find_by_key(op_entry->obj, "argc");
            const char *name = NULL;
            size_t name_len = 0;
            uint32_t argc = 0;
            if (!name_entry || !argc_entry ||
                !entry_as_string(name_entry, &name, &name_len) ||
                !entry_as_u32(argc_entry, &argc)) {
                ast_err(err, err_cap, "CALL expects name and argc");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_n(out, name, name_len);
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)argc);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 3 && memcmp(op_name, "JMP", 3) == 0) {
            ObjEntry *target_entry = object_find_by_key(op_entry->obj, "target");
            uint32_t target = 0;
            if (!target_entry || !entry_as_u32(target_entry, &target)) {
                ast_err(err, err_cap, "JMP expects target");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)target);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 12 && memcmp(op_name, "JMP_IF_FALSE", 12) == 0) {
            ObjEntry *target_entry = object_find_by_key(op_entry->obj, "target");
            uint32_t target = 0;
            if (!target_entry || !entry_as_u32(target_entry, &target)) {
                ast_err(err, err_cap, "JMP_IF_FALSE expects target");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)target);
            sb_append_n(out, buf, strlen(buf));
        }

        sb_append_char(out, '\n');
    }

    return 1;
}

static void sb_free(StrBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static char *read_file_bytes(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 > cap) {
            size_t next = cap * 2;
            char *tmp = (char*)realloc(buf, next);
            if (!tmp) {
                free(buf);
                fclose(fp);
                return NULL;
            }
            buf = tmp;
            cap = next;
        }
        buf[len++] = (char)c;
    }
    fclose(fp);
    *out_len = len;
    return buf;
}

static int write_file_bytes(const char *path, const char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t wrote = fwrite(data, 1, len, fp);
    fclose(fp);
    return wrote == len;
}

static void native_print(VM *vm, List *stack, List *global)
{
    (void)vm;
    (void)global;
    uint32_t argc = native_argc(vm, global);
    if (argc == 0) {
        if (stack->size > 2) {
            ObjEntry *entry = (ObjEntry*)stack->data[stack->size - 1].p;
            print_plain_entry(stdout, entry);
            return;
        }
        fputs("(stack empty)", stdout);
        return;
    }
    for (uint32_t i = 0; i < argc; i++) {
        ObjEntry *entry = native_arg(stack, argc, i);
        if (i) fputc(' ', stdout);
        print_entry(stdout, entry);
    }
    fputc('\n', stdout);
}

static void native_println(VM *vm, List *stack, List *global)
{
    (void)vm;
    (void)global;
    uint32_t argc = native_argc(vm, global);
    if (argc == 0) {
        if (stack->size > 2) {
            ObjEntry *entry = (ObjEntry*)stack->data[stack->size - 1].p;
            print_plain_entry(stdout, entry);
        }
        fputc('\n', stdout);
        return;
    }
    for (uint32_t i = 0; i < argc; i++) {
        ObjEntry *entry = native_arg(stack, argc, i);
        if (i) fputc(' ', stdout);
        print_plain_entry(stdout, entry);
    }
    fputc('\n', stdout);
}

static void native_len(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "len expects a value\n");
        return;
    }
    Int length = urb_value_len(target->obj);
    push_number(vm, stack, (Float)length);
}

static void native_pretty(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "pretty expects a value\n");
        return;
    }
    ObjEntry *out = vm_pretty_value(vm, target);
    urb_object_add(stack, out);
}

static void native_read(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *path = NULL;
    size_t path_len = 0;
    if (!entry_as_string(arg0, &path, &path_len)) {
        fprintf(stderr, "read expects a string path\n");
        return;
    }
    char *path_buf = (char*)malloc(path_len + 1);
    if (!path_buf) {
        fprintf(stderr, "read out of memory\n");
        return;
    }
    memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;
    size_t len = 0;
    char *data = read_file_bytes(path_buf, &len);
    free(path_buf);
    if (!data && len == 0) {
        fprintf(stderr, "read failed\n");
        urb_object_add(stack, vm->null_entry);
        return;
    }
    ObjEntry *out = vm_make_char_value(vm, data ? data : "", len);
    free(data);
    urb_object_add(stack, out);
}

static void native_write(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    ObjEntry *arg1 = native_arg(stack, argc, 1);
    const char *path = NULL;
    size_t path_len = 0;
    if (!entry_as_string(arg0, &path, &path_len)) {
        fprintf(stderr, "write expects a string path\n");
        return;
    }
    ObjEntry *data_entry = arg1;
    if (!data_entry) {
        fprintf(stderr, "write expects data\n");
        return;
    }
    ObjEntry *string_entry = NULL;
    const char *data = NULL;
    size_t data_len = 0;
    if (!entry_as_string(data_entry, &data, &data_len)) {
        string_entry = vm_stringify_value(vm, data_entry, 1);
        data = urb_char_data(string_entry->obj);
        data_len = urb_char_len(string_entry->obj);
    }
    char *path_buf = (char*)malloc(path_len + 1);
    if (!path_buf) {
        fprintf(stderr, "write out of memory\n");
        return;
    }
    memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;
    int ok = write_file_bytes(path_buf, data, data_len);
    free(path_buf);
    push_number(vm, stack, ok ? 1.0f : 0.0f);
}

static void native_eval(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    const char *src = NULL;
    size_t len = 0;
    if (!entry_as_string(target, &src, &len)) {
        fprintf(stderr, "eval expects a string\n");
        return;
    }
    char *buf = (char*)malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "eval out of memory\n");
        return;
    }
    memcpy(buf, src, len);
    buf[len] = 0;
    vm_exec_line(vm, buf);
    free(buf);
    urb_object_add(stack, vm->null_entry);
}

static void native_parse(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    const char *src = NULL;
    size_t len = 0;
    if (!entry_as_string(target, &src, &len)) {
        fprintf(stderr, "parse expects a string\n");
        return;
    }
    char *buf = (char*)malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "parse out of memory\n");
        return;
    }
    memcpy(buf, src, len);
    buf[len] = 0;

    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!vm_compile_source(buf, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "parse error");
        free(buf);
        return;
    }
    free(buf);

    ObjEntry *ast = vm_bytecode_to_ast(vm, bc.data, bc.len);
    bc_free(&bc);
    if (!ast) {
        fprintf(stderr, "parse failed to build AST\n");
        return;
    }
    urb_object_add(stack, ast);
}

static void native_emit(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!ast_to_bytecode(vm, target, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "emit failed");
        return;
    }
    ObjEntry *bytes = vm_make_byte_value(vm, (const char*)bc.data, bc.len);
    bc_free(&bc);
    urb_object_add(stack, bytes);
}

static void native_eval_bytecode(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    const char *data = NULL;
    size_t len = 0;
    if (!entry_as_string(target, &data, &len)) {
        fprintf(stderr, "eval_bytecode expects byte/string data\n");
        return;
    }
    vm_exec_bytecode(vm, (const unsigned char*)data, len);
    urb_object_add(stack, vm->null_entry);
}

static void native_bytecode_to_ast(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    const char *data = NULL;
    size_t len = 0;
    if (!entry_as_string(target, &data, &len)) {
        fprintf(stderr, "bytecode_to_ast expects byte/string data\n");
        return;
    }
    ObjEntry *ast = vm_bytecode_to_ast(vm, (const unsigned char*)data, len);
    if (!ast) {
        fprintf(stderr, "bytecode_to_ast failed\n");
        return;
    }
    urb_object_add(stack, ast);
}

static void native_ast_to_source(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    StrBuf out;
    sb_init(&out);
    char err[256];
    err[0] = 0;
    if (!ast_to_source(vm, target, &out, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "ast_to_source failed");
        sb_free(&out);
        return;
    }
    push_string(vm, stack, out.data, out.len);
    sb_free(&out);
}

static void native_gc(VM *vm, List *stack, List *global)
{
    (void)global;
    if (vm) vm_gc(vm);
    if (vm) {
        urb_object_add(stack, vm->null_entry);
    }
}

static void native_gc_collect(VM *vm, List *stack, List *global)
{
    (void)global;
    if (vm) vm_gc(vm);
    if (vm) {
        urb_object_add(stack, vm->null_entry);
    }
}

static void native_append(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *self = native_this(vm);
    ObjEntry *dst = NULL;
    ObjEntry *src = NULL;
    if (self) {
        dst = self;
        src = native_arg(stack, argc, 0);
    } else {
        dst = native_arg(stack, argc, 0);
        src = native_arg(stack, argc, 1);
    }
    if (!dst || !src) {
        fprintf(stderr, "append expects target and source\n");
        return;
    }

    Int dst_type = urb_obj_type(dst->obj);
    Int src_type = urb_obj_type(src->obj);
    if (!((dst_type == URB_T_CHAR || dst_type == URB_T_BYTE) &&
          (src_type == URB_T_CHAR || src_type == URB_T_BYTE))) {
        fprintf(stderr, "append expects string values\n");
        return;
    }

    urb_bytes_append(dst->obj, urb_char_data(src->obj), urb_char_len(src->obj));
}

static int native_number_seed(VM *vm, List *stack, List *global, Float *out, uint32_t *start)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *self = native_this(vm);
    if (self && entry_as_number(self, out)) {
        *start = 0;
        return 1;
    }
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    if (!arg0 || !entry_as_number(arg0, out)) return 0;
    *start = 1;
    return 1;
}

static void native_add(VM *vm, List *stack, List *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "add expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm, global);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "add expects numbers\n");
            return;
        }
        acc += v;
    }
    push_number(vm, stack, acc);
}

static void native_sub(VM *vm, List *stack, List *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "sub expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm, global);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "sub expects numbers\n");
            return;
        }
        acc -= v;
    }
    push_number(vm, stack, acc);
}

static void native_mul(VM *vm, List *stack, List *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "mul expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm, global);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "mul expects numbers\n");
            return;
        }
        acc *= v;
    }
    push_number(vm, stack, acc);
}

static void native_div(VM *vm, List *stack, List *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "div expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm, global);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "div expects numbers\n");
            return;
        }
        acc /= v;
    }
    push_number(vm, stack, acc);
}

static void native_mod(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *self = native_this(vm);
    Float a = 0;
    Float b = 0;
    if (self && entry_as_number(self, &a)) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!arg0 || !entry_as_number(arg0, &b)) {
            fprintf(stderr, "mod expects numbers\n");
            return;
        }
    } else {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!arg0 || !arg1 || !entry_as_number(arg0, &a) || !entry_as_number(arg1, &b)) {
            fprintf(stderr, "mod expects numbers\n");
            return;
        }
    }
    push_number(vm, stack, (Float)fmod((double)a, (double)b));
}

static void native_pow(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *self = native_this(vm);
    Float base = 0;
    Float exp = 0;
    if (self && entry_as_number(self, &base)) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!arg0 || !entry_as_number(arg0, &exp)) {
            fprintf(stderr, "pow expects numbers\n");
            return;
        }
    } else {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!arg0 || !arg1 || !entry_as_number(arg0, &base) || !entry_as_number(arg1, &exp)) {
            fprintf(stderr, "pow expects numbers\n");
            return;
        }
    }
    push_number(vm, stack, (Float)pow((double)base, (double)exp));
}

static void native_min(VM *vm, List *stack, List *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "min expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm, global);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "min expects numbers\n");
            return;
        }
        if (v < acc) acc = v;
    }
    push_number(vm, stack, acc);
}

static void native_max(VM *vm, List *stack, List *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "max expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm, global);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "max expects numbers\n");
            return;
        }
        if (v > acc) acc = v;
    }
    push_number(vm, stack, acc);
}

static int native_unary_number(VM *vm, List *stack, List *global, Float *out)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *self = native_this(vm);
    if (self && entry_as_number(self, out)) return 1;
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    if (!arg0 || !entry_as_number(arg0, out)) return 0;
    return 1;
}

static void native_abs(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "abs expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)fabs((double)v));
}

static void native_floor(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "floor expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)floor((double)v));
}

static void native_ceil(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "ceil expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)ceil((double)v));
}

static void native_round(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "round expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)round((double)v));
}

static void native_sqrt(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "sqrt expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)sqrt((double)v));
}

static void native_sin(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "sin expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)sin((double)v));
}

static void native_cos(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "cos expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)cos((double)v));
}

static void native_tan(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "tan expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)tan((double)v));
}

static void native_asin(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "asin expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)asin((double)v));
}

static void native_acos(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "acos expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)acos((double)v));
}

static void native_atan(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "atan expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)atan((double)v));
}

static void native_log(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "log expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)log((double)v));
}

static void native_exp(VM *vm, List *stack, List *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "exp expects a number\n");
        return;
    }
    push_number(vm, stack, (Float)exp((double)v));
}

static ObjEntry *native_string_target(VM *vm, List *stack, uint32_t argc)
{
    ObjEntry *self = native_this(vm);
    if (self && (urb_obj_type(self->obj) == URB_T_CHAR || urb_obj_type(self->obj) == URB_T_BYTE)) return self;
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    if (arg0 && (urb_obj_type(arg0->obj) == URB_T_CHAR || urb_obj_type(arg0->obj) == URB_T_BYTE)) return arg0;
    return NULL;
}

static int number_to_int(ObjEntry *entry, Int *out)
{
    if (!entry || urb_obj_type(entry->obj) != URB_T_NUMBER || entry->obj->size < 3) return 0;
    Float v = entry->obj->data[2].f;
    Int iv = (Int)v;
    if ((Float)iv != v) return 0;
    *out = iv;
    return 1;
}

static Int list_pos_from_index(List *obj, Int index)
{
    Int size = (Int)(obj->size - 2);
    if (index < 0) index = size + index;
    return index + 2;
}

static int list_index_valid(List *obj, Int index)
{
    Int size = (Int)(obj->size - 2);
    if (index < 0) index = size + index;
    return index >= 0 && index < size;
}

static void native_slice(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "slice expects a string target\n");
        return;
    }
    const char *s = urb_char_data(target->obj);
    size_t len = urb_char_len(target->obj);
    Int start = 0;
    Int end = (Int)len;
    if (argc >= 1) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!number_to_int(arg0, &start)) {
            fprintf(stderr, "slice expects numeric start\n");
            return;
        }
        if (start < 0) start = (Int)len + start;
        if (start < 0) start = 0;
        if ((size_t)start > len) start = (Int)len;
    }
    if (argc >= 2) {
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!number_to_int(arg1, &end)) {
            fprintf(stderr, "slice expects numeric end\n");
            return;
        }
        if (end < 0) end = (Int)len + end;
        if (end < 0) end = 0;
        if ((size_t)end > len) end = (Int)len;
    }
    if (end < start) end = start;
    push_string(vm, stack, s + start, (size_t)(end - start));
}

static void native_substr(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "substr expects a string target\n");
        return;
    }
    const char *s = urb_char_data(target->obj);
    size_t len = urb_char_len(target->obj);
    Int start = 0;
    Int count = (Int)len;
    if (argc >= 1) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!number_to_int(arg0, &start)) {
            fprintf(stderr, "substr expects numeric start\n");
            return;
        }
        if (start < 0) start = 0;
        if ((size_t)start > len) start = (Int)len;
    }
    if (argc >= 2) {
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!number_to_int(arg1, &count)) {
            fprintf(stderr, "substr expects numeric length\n");
            return;
        }
        if (count < 0) count = 0;
    } else {
        count = (Int)len - start;
    }
    if ((size_t)(start + count) > len) count = (Int)len - start;
    push_string(vm, stack, s + start, (size_t)count);
}

static void native_upper(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "upper expects a string target\n");
        return;
    }
    size_t len = urb_char_len(target->obj);
    char *buf = (char*)malloc(len);
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)toupper((unsigned char)urb_char_data(target->obj)[i]);
    }
    push_string(vm, stack, buf, len);
    free(buf);
}

static void native_lower(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "lower expects a string target\n");
        return;
    }
    size_t len = urb_char_len(target->obj);
    char *buf = (char*)malloc(len);
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)tolower((unsigned char)urb_char_data(target->obj)[i]);
    }
    push_string(vm, stack, buf, len);
    free(buf);
}

static void native_trim(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "trim expects a string target\n");
        return;
    }
    const char *s = urb_char_data(target->obj);
    size_t len = urb_char_len(target->obj);
    size_t start = 0;
    size_t end = len;
    while (start < len && isspace((unsigned char)s[start])) start++;
    while (end > start && isspace((unsigned char)s[end - 1])) end--;
    push_string(vm, stack, s + start, end - start);
}

static void native_starts_with(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "startsWith expects a string target\n");
        return;
    }
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *needle = NULL;
    size_t nlen = 0;
    if (!entry_as_string(arg0, &needle, &nlen)) {
        fprintf(stderr, "startsWith expects a string\n");
        return;
    }
    const char *s = urb_char_data(target->obj);
    size_t len = urb_char_len(target->obj);
    int ok = nlen <= len && memcmp(s, needle, nlen) == 0;
    push_number(vm, stack, ok ? 1 : 0);
}

static void native_ends_with(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "endsWith expects a string target\n");
        return;
    }
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *needle = NULL;
    size_t nlen = 0;
    if (!entry_as_string(arg0, &needle, &nlen)) {
        fprintf(stderr, "endsWith expects a string\n");
        return;
    }
    const char *s = urb_char_data(target->obj);
    size_t len = urb_char_len(target->obj);
    int ok = nlen <= len && memcmp(s + (len - nlen), needle, nlen) == 0;
    push_number(vm, stack, ok ? 1 : 0);
}

static void native_split(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "split expects a string target\n");
        return;
    }
    const char *s = urb_char_data(target->obj);
    size_t len = urb_char_len(target->obj);
    const char *delim = "";
    size_t dlen = 0;
    if (argc >= 1) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!entry_as_string(arg0, &delim, &dlen)) {
            fprintf(stderr, "split expects a string delimiter\n");
            return;
        }
    }

    ObjEntry *out = vm_make_object_value(vm, 8);
    if (dlen == 0) {
        for (size_t i = 0; i < len; i++) {
            ObjEntry *part = vm_make_char_value(vm, s + i, 1);
            urb_object_add(out->obj, part);
        }
        urb_object_add(stack, out);
        return;
    }

    size_t pos = 0;
    while (pos <= len) {
        size_t next = pos;
        while (next + dlen <= len && memcmp(s + next, delim, dlen) != 0) next++;
        ObjEntry *part = vm_make_char_value(vm, s + pos, next - pos);
        urb_object_add(out->obj, part);
        pos = next + dlen;
        if (next + dlen > len) break;
    }
    urb_object_add(stack, out);
}

static void native_join(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target || urb_obj_type(target->obj) != URB_T_OBJECT) {
        fprintf(stderr, "join expects an object/array target\n");
        return;
    }
    const char *delim = "";
    size_t dlen = 0;
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    if (arg0 && urb_obj_type(arg0->obj) == URB_T_CHAR) {
        delim = urb_char_data(arg0->obj);
        dlen = urb_char_len(arg0->obj);
    }

    StrBuf buf;
    sb_init(&buf);
    for (Int i = 2; i < target->obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)target->obj->data[i].p;
        if (i > 2 && dlen) sb_append_n(&buf, delim, dlen);
        ObjEntry *str = vm_stringify_value(vm, entry, 1);
        sb_append_n(&buf, urb_char_data(str->obj), urb_char_len(str->obj));
    }
    push_string(vm, stack, buf.data, buf.len);
    sb_free(&buf);
}

static char *papagaio_process_pairs(
    const char *input,
    const char **patterns,
    const char **repls,
    int pair_count
)
{
    Symbols sym = { "$", "{", "}" };
    Rule *rules = (Rule*)malloc(sizeof(Rule) * pair_count);
    for (int i = 0; i < pair_count; i++) {
        parse_pattern_ex(patterns[i], &rules[i].pattern, &sym);
        rules[i].replacement = repls[i];
    }

    StrBuf out;
    sb_init(&out);
    int len = (int)strlen(input);
    int pos = 0;
    while (pos < len) {
        int matched = 0;
        for (int i = 0; i < pair_count; i++) {
            Match m;
            if (match_pattern(input, &rules[i].pattern, pos, &m)) {
                char *r = apply_replacement_ex(rules[i].replacement, &m, sym.sigil);
                sb_append_n(&out, r, strlen(r));
                free(r);
                pos = m.end;
                free(m.cap);
                matched = 1;
                break;
            }
        }
        if (!matched) {
            sb_append_char(&out, input[pos++]);
        }
    }

    for (int i = 0; i < pair_count; i++) {
        free(rules[i].pattern.t);
    }
    free(rules);
    return out.data;
}

static void native_replace(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "replace expects a string target\n");
        return;
    }
    if (argc < 2 || (argc % 2) != 0) {
        fprintf(stderr, "replace expects pattern/replacement pairs\n");
        return;
    }

    const char *input = urb_char_data(target->obj);
    size_t input_len = urb_char_len(target->obj);
    char *input_c = (char*)malloc(input_len + 1);
    memcpy(input_c, input, input_len);
    input_c[input_len] = 0;

    int pair_count = (int)(argc / 2);
    char **patterns = (char**)calloc((size_t)pair_count, sizeof(char*));
    char **repls = (char**)calloc((size_t)pair_count, sizeof(char*));
    for (int i = 0; i < pair_count; i++) {
        ObjEntry *pat = native_arg(stack, argc, (uint32_t)(i * 2));
        ObjEntry *rep = native_arg(stack, argc, (uint32_t)(i * 2 + 1));
        const char *p = NULL;
        size_t plen = 0;
        const char *r = NULL;
        size_t rlen = 0;
        if (!entry_as_string(pat, &p, &plen) || !entry_as_string(rep, &r, &rlen)) {
            fprintf(stderr, "replace expects string patterns and replacements\n");
            free(input_c);
            free(patterns);
            free(repls);
            return;
        }
        patterns[i] = (char*)malloc(plen + 1);
        memcpy(patterns[i], p, plen);
        patterns[i][plen] = 0;
        repls[i] = (char*)malloc(rlen + 1);
        memcpy(repls[i], r, rlen);
        repls[i][rlen] = 0;
    }

    char *out = papagaio_process_pairs(input_c, (const char**)patterns, (const char**)repls, pair_count);
    push_string(vm, stack, out, strlen(out));
    free(out);
    free(input_c);
    for (int i = 0; i < pair_count; i++) {
        free(patterns[i]);
        free(repls[i]);
    }
    free(patterns);
    free(repls);
}

static Int clamp_index(Int i, Int len)
{
    if (i < 0) i = len + i;      // suporta negativos tipo slice
    if (i < 0) i = 0;
    if (i > len) i = len;
    return i;
}

static void native_find(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "find expects a string target\n");
        return;
    }

    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *needle = NULL;
    size_t nlen = 0;
    if (!entry_as_string(arg0, &needle, &nlen)) {
        fprintf(stderr, "find expects a string needle\n");
        return;
    }

    Int start = 0;
    if (argc >= 2) {
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!number_to_int(arg1, &start)) {
            fprintf(stderr, "find expects integer start\n");
            return;
        }
    }

    const char *hay = urb_char_data(target->obj);
    size_t hlen_sz = urb_char_len(target->obj);
    Int hlen = (Int)hlen_sz;

    start = clamp_index(start, hlen);

    if (nlen == 0) { // convenção: string vazia "casa" no start
        push_number(vm, stack, (Float)start);
        return;
    }

    if ((size_t)start > hlen_sz || nlen > hlen_sz) {
        push_number(vm, stack, -1.0f);
        return;
    }

    size_t last = hlen_sz - nlen;
    for (size_t i = (size_t)start; i <= last; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            push_number(vm, stack, (Float)(Int)i);
            return;
        }
    }

    push_number(vm, stack, -1.0f);
}

static void native_rfind(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "rfind expects a string target\n");
        return;
    }

    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *needle = NULL;
    size_t nlen = 0;
    if (!entry_as_string(arg0, &needle, &nlen)) {
        fprintf(stderr, "rfind expects a string needle\n");
        return;
    }

    const char *hay = urb_char_data(target->obj);
    size_t hlen_sz = urb_char_len(target->obj);
    Int hlen = (Int)hlen_sz;

    // start aqui é o "limite superior" (posição onde a busca reversa pode começar).
    // default: final da string
    Int start = hlen;
    if (argc >= 2) {
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!number_to_int(arg1, &start)) {
            fprintf(stderr, "rfind expects integer start\n");
            return;
        }
    }
    start = clamp_index(start, hlen);

    if (nlen == 0) { // string vazia: casa no start (igual find)
        push_number(vm, stack, (Float)start);
        return;
    }

    if (nlen > hlen_sz) {
        push_number(vm, stack, -1.0f);
        return;
    }

    // último índice possível de início é (hlen - nlen)
    Int max_i = (Int)(hlen_sz - nlen);
    if (start > max_i) start = max_i;
    if (start < 0) {
        push_number(vm, stack, -1.0f);
        return;
    }

    for (Int i = start; i >= 0; i--) {
        if (memcmp(hay + (size_t)i, needle, nlen) == 0) {
            push_number(vm, stack, (Float)i);
            return;
        }
    }

    push_number(vm, stack, -1.0f);
}

static void native_contains(VM *vm, List *stack, List *global)
{
    // contains(needle, start?) -> 1/0
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "contains expects a string target\n");
        return;
    }

    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *needle = NULL;
    size_t nlen = 0;
    if (!entry_as_string(arg0, &needle, &nlen)) {
        fprintf(stderr, "contains expects a string needle\n");
        return;
    }

    Int start = 0;
    if (argc >= 2) {
        ObjEntry *arg1 = native_arg(stack, argc, 1);
        if (!number_to_int(arg1, &start)) {
            fprintf(stderr, "contains expects integer start\n");
            return;
        }
    }

    const char *hay = urb_char_data(target->obj);
    size_t hlen = urb_char_len(target->obj);
    Int hlen_i = (Int)hlen;
    start = clamp_index(start, hlen_i);

    if (nlen == 0) { push_number(vm, stack, 1.0f); return; }
    if (nlen > hlen || (size_t)start > hlen - nlen) { push_number(vm, stack, 0.0f); return; }

    size_t last = hlen - nlen;
    for (size_t i = (size_t)start; i <= last; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            push_number(vm, stack, 1.0f);
            return;
        }
    }
    push_number(vm, stack, 0.0f);
}

static ObjEntry *native_object_target(VM *vm, List *stack, uint32_t argc)
{
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target || urb_obj_type(target->obj) != URB_T_OBJECT) return NULL;
    return target;
}

static void native_keys(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_object_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "keys expects object target\n");
        return;
    }
    ObjEntry *out = vm_make_object_value(vm, target->obj->size - 2);
    for (Int i = 2; i < target->obj->size; i++) {
        ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
        ObjEntry *key = child ? urb_obj_key(child->obj) : NULL;
        if (!key || urb_obj_type(key->obj) != URB_T_CHAR) continue;
        ObjEntry *entry = vm_make_char_value(vm, urb_char_data(key->obj), urb_char_len(key->obj));
        urb_object_add(out->obj, entry);
    }
    urb_object_add(stack, out);
}

static void native_values(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_object_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "values expects object target\n");
        return;
    }
    ObjEntry *out = vm_make_object_value(vm, target->obj->size - 2);
    for (Int i = 2; i < target->obj->size; i++) {
        ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
        if (!child) continue;
        urb_object_add(out->obj, child);
    }
    urb_object_add(stack, out);
}

static void native_has(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    ObjEntry *idx = native_arg(stack, argc, 0);
    if (!target || !idx) {
        fprintf(stderr, "has expects target and key/index\n");
        return;
    }

    Int type = urb_obj_type(target->obj);
    if (urb_obj_type(idx->obj) == URB_T_CHAR && type == URB_T_OBJECT) {
        const char *key = urb_char_data(idx->obj);
        size_t len = urb_char_len(idx->obj);
        for (Int i = 2; i < target->obj->size; i++) {
            ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
            ObjEntry *k = child ? urb_obj_key(child->obj) : NULL;
            if (!k || urb_obj_type(k->obj) != URB_T_CHAR) continue;
            if (urb_char_len(k->obj) == len && memcmp(urb_char_data(k->obj), key, len) == 0) {
                push_number(vm, stack, 1);
                return;
            }
        }
        push_number(vm, stack, 0);
        return;
    }

    if (urb_obj_type(idx->obj) == URB_T_NUMBER) {
        Int i = 0;
        if (!number_to_int(idx, &i)) {
            fprintf(stderr, "has expects integer index\n");
            return;
        }
        Int size = urb_value_len(target->obj);
        if (i < 0) i = size + i;
        if (i < 0 || i >= size) {
            push_number(vm, stack, 0);
            return;
        }
        push_number(vm, stack, 1);
        return;
    }

    fprintf(stderr, "has expects object key or numeric index\n");
}

static void native_delete(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    ObjEntry *idx = native_arg(stack, argc, 0);
    if (!target || !idx) {
        fprintf(stderr, "delete expects target and key/index\n");
        return;
    }

    Int type = urb_obj_type(target->obj);
    if (urb_obj_type(idx->obj) == URB_T_CHAR && type == URB_T_OBJECT) {
        const char *key = urb_char_data(idx->obj);
        size_t len = urb_char_len(idx->obj);
        for (Int i = 2; i < target->obj->size; i++) {
            ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
            ObjEntry *k = child ? urb_obj_key(child->obj) : NULL;
            if (!k || urb_obj_type(k->obj) != URB_T_CHAR) continue;
            if (urb_char_len(k->obj) == len && memcmp(urb_char_data(k->obj), key, len) == 0) {
                urb_remove(target->obj, i);
                push_number(vm, stack, 1);
                return;
            }
        }
        push_number(vm, stack, 0);
        return;
    }

    if (urb_obj_type(idx->obj) == URB_T_NUMBER) {
        Int i = 0;
        if (!number_to_int(idx, &i)) {
            fprintf(stderr, "delete expects integer index\n");
            return;
        }
        if (!list_index_valid(target->obj, i)) {
            push_number(vm, stack, 0);
            return;
        }
        if (type == URB_T_OBJECT || type == URB_T_NUMBER) {
            urb_remove(target->obj, list_pos_from_index(target->obj, i));
            push_number(vm, stack, 1);
            return;
        }
        if (type == URB_T_CHAR || type == URB_T_BYTE) {
            size_t len = urb_char_len(target->obj);
            if (i < 0) i = (Int)len + i;
            if (i < 0 || (size_t)i >= len) {
                push_number(vm, stack, 0);
                return;
            }
            size_t pos = (size_t)i;
            memmove(urb_char_data(target->obj) + pos,
                    urb_char_data(target->obj) + pos + 1,
                    len - pos - 1);
            target->obj->size = (UHalf)(target->obj->size - 1);
            target->obj->capacity = target->obj->size;
            push_number(vm, stack, 1);
            return;
        }
    }

    fprintf(stderr, "delete expects object key or numeric index\n");
}

static void native_push(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "push expects target\n");
        return;
    }
    uint32_t start = native_this(vm) ? 0 : 1;
    Int type = urb_obj_type(target->obj);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        if (!arg) continue;
        if (type == URB_T_OBJECT) {
            urb_object_add(target->obj, arg);
        } else if (type == URB_T_NUMBER) {
            Float v = 0;
            if (!entry_as_number(arg, &v)) {
                fprintf(stderr, "push expects number values\n");
                return;
            }
            Value val;
            val.f = v;
            urb_push(target->obj, val);
        } else if (type == URB_T_CHAR || type == URB_T_BYTE) {
            Int at = urb_obj_type(arg->obj);
            if (at != URB_T_CHAR && at != URB_T_BYTE) {
                fprintf(stderr, "push expects string values\n");
                return;
            }
            urb_bytes_append(target->obj, urb_char_data(arg->obj), urb_char_len(arg->obj));
        }
    }
}

static void native_pop(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "pop expects target\n");
        return;
    }
    Int type = urb_obj_type(target->obj);
    if (type == URB_T_OBJECT) {
        if (target->obj->size <= 2) return;
        Value v = urb_pop(target->obj);
        ObjEntry *entry = (ObjEntry*)v.p;
        if (entry) urb_object_add(stack, entry);
        return;
    }
    if (type == URB_T_NUMBER) {
        if (target->obj->size <= 2) return;
        Value v = urb_pop(target->obj);
        push_number(vm, stack, v.f);
        return;
    }
    if (type == URB_T_CHAR || type == URB_T_BYTE) {
        size_t len = urb_char_len(target->obj);
        if (!len) return;
        char c = urb_char_data(target->obj)[len - 1];
        target->obj->size = (UHalf)(target->obj->size - 1);
        target->obj->capacity = target->obj->size;
        push_string(vm, stack, &c, 1);
        return;
    }
}

static void native_shift(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "shift expects target\n");
        return;
    }
    Int type = urb_obj_type(target->obj);
    if (type == URB_T_OBJECT) {
        if (target->obj->size <= 2) return;
        Value v = urb_remove(target->obj, 2);
        ObjEntry *entry = (ObjEntry*)v.p;
        if (entry) urb_object_add(stack, entry);
        return;
    }
    if (type == URB_T_NUMBER) {
        if (target->obj->size <= 2) return;
        Value v = urb_remove(target->obj, 2);
        push_number(vm, stack, v.f);
        return;
    }
    if (type == URB_T_CHAR || type == URB_T_BYTE) {
        size_t len = urb_char_len(target->obj);
        if (!len) return;
        char c = urb_char_data(target->obj)[0];
        memmove(urb_char_data(target->obj), urb_char_data(target->obj) + 1, len - 1);
        target->obj->size = (UHalf)(target->obj->size - 1);
        target->obj->capacity = target->obj->size;
        push_string(vm, stack, &c, 1);
        return;
    }
}

static void native_unshift(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "unshift expects target\n");
        return;
    }
    uint32_t start = native_this(vm) ? 0 : 1;
    Int type = urb_obj_type(target->obj);
    for (uint32_t i = argc; i-- > start;) {
        ObjEntry *arg = native_arg(stack, argc, i);
        if (!arg) continue;
        if (type == URB_T_OBJECT) {
            Value v;
            v.p = arg;
            urb_insert(target->obj, 2, v);
        } else if (type == URB_T_NUMBER) {
            Float v = 0;
            if (!entry_as_number(arg, &v)) {
                fprintf(stderr, "unshift expects number values\n");
                return;
            }
            Value val;
            val.f = v;
            urb_insert(target->obj, 2, val);
        } else if (type == URB_T_CHAR || type == URB_T_BYTE) {
            Int at = urb_obj_type(arg->obj);
            if (at != URB_T_CHAR && at != URB_T_BYTE) {
                fprintf(stderr, "unshift expects string values\n");
                return;
            }
            size_t len = urb_char_len(target->obj);
            size_t add = urb_char_len(arg->obj);
            target->obj->data = (Value*)realloc(target->obj->data, 2 * sizeof(Value) + len + add);
            memmove(urb_char_data(target->obj) + add, urb_char_data(target->obj), len);
            memcpy(urb_char_data(target->obj), urb_char_data(arg->obj), add);
            target->obj->size = (UHalf)(len + add + 2);
            target->obj->capacity = target->obj->size;
        }
    }
}

static void native_insert(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    ObjEntry *idx = native_arg(stack, argc, 0);
    ObjEntry *val = native_arg(stack, argc, 1);
    if (!target || !idx || !val) {
        fprintf(stderr, "insert expects target, index, value\n");
        return;
    }
    Int index = 0;
    if (!number_to_int(idx, &index)) {
        fprintf(stderr, "insert expects integer index\n");
        return;
    }
    Int type = urb_obj_type(target->obj);
    if (type == URB_T_OBJECT) {
        Value v;
        v.p = val;
        urb_insert(target->obj, list_pos_from_index(target->obj, index), v);
        return;
    }
    if (type == URB_T_NUMBER) {
        Float v = 0;
        if (!entry_as_number(val, &v)) {
            fprintf(stderr, "insert expects number value\n");
            return;
        }
        Value nv;
        nv.f = v;
        urb_insert(target->obj, list_pos_from_index(target->obj, index), nv);
        return;
    }
    if (type == URB_T_CHAR || type == URB_T_BYTE) {
        Int vt = urb_obj_type(val->obj);
        if (vt != URB_T_CHAR && vt != URB_T_BYTE) {
            fprintf(stderr, "insert expects string value\n");
            return;
        }
        size_t len = urb_char_len(target->obj);
        size_t add = urb_char_len(val->obj);
        if (index < 0) index = (Int)len + index;
        if (index < 0) index = 0;
        if ((size_t)index > len) index = (Int)len;
        target->obj->data = (Value*)realloc(target->obj->data, 2 * sizeof(Value) + len + add);
        memmove(urb_char_data(target->obj) + index + add,
                urb_char_data(target->obj) + index,
                len - (size_t)index);
        memcpy(urb_char_data(target->obj) + index, urb_char_data(val->obj), add);
        target->obj->size = (UHalf)(len + add + 2);
        target->obj->capacity = target->obj->size;
        return;
    }
}

static void native_remove(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    ObjEntry *idx = native_arg(stack, argc, 0);
    if (!target || !idx) {
        fprintf(stderr, "remove expects target and index\n");
        return;
    }
    Int index = 0;
    if (!number_to_int(idx, &index)) {
        fprintf(stderr, "remove expects integer index\n");
        return;
    }
    Int type = urb_obj_type(target->obj);
    if (type == URB_T_OBJECT) {
        if (target->obj->size <= 2) return;
        Value v = urb_remove(target->obj, list_pos_from_index(target->obj, index));
        ObjEntry *entry = (ObjEntry*)v.p;
        if (entry) urb_object_add(stack, entry);
        return;
    }
    if (type == URB_T_NUMBER) {
        if (target->obj->size <= 2) return;
        Value v = urb_remove(target->obj, list_pos_from_index(target->obj, index));
        push_number(vm, stack, v.f);
        return;
    }
    if (type == URB_T_CHAR || type == URB_T_BYTE) {
        size_t len = urb_char_len(target->obj);
        if (index < 0) index = (Int)len + index;
        if (index < 0 || (size_t)index >= len) return;
        char c = urb_char_data(target->obj)[index];
        memmove(urb_char_data(target->obj) + index,
                urb_char_data(target->obj) + index + 1,
                len - (size_t)index - 1);
        target->obj->size = (UHalf)(target->obj->size - 1);
        target->obj->capacity = target->obj->size;
        push_string(vm, stack, &c, 1);
        return;
    }
}

NativeFn vm_lookup_native(const char *name)
{
    if (strcmp(name, "print") == 0) return native_print;
    if (strcmp(name, "println") == 0) return native_println;
    if (strcmp(name, "len") == 0) return native_len;
    if (strcmp(name, "pretty") == 0) return native_pretty;
    if (strcmp(name, "read") == 0) return native_read;
    if (strcmp(name, "write") == 0) return native_write;
    if (strcmp(name, "eval") == 0) return native_eval;
    if (strcmp(name, "parse") == 0) return native_parse;
    if (strcmp(name, "emit") == 0) return native_emit;
    if (strcmp(name, "eval_bytecode") == 0) return native_eval_bytecode;
    if (strcmp(name, "bytecode_to_ast") == 0) return native_bytecode_to_ast;
    if (strcmp(name, "ast_to_source") == 0) return native_ast_to_source;
    if (strcmp(name, "gc") == 0) return native_gc;
    if (strcmp(name, "gc_collect") == 0) return native_gc_collect;
    if (strcmp(name, "append") == 0) return native_append;
    if (strcmp(name, "add") == 0) return native_add;
    if (strcmp(name, "sub") == 0) return native_sub;
    if (strcmp(name, "mul") == 0) return native_mul;
    if (strcmp(name, "div") == 0) return native_div;
    if (strcmp(name, "mod") == 0) return native_mod;
    if (strcmp(name, "pow") == 0) return native_pow;
    if (strcmp(name, "min") == 0) return native_min;
    if (strcmp(name, "max") == 0) return native_max;
    if (strcmp(name, "abs") == 0) return native_abs;
    if (strcmp(name, "floor") == 0) return native_floor;
    if (strcmp(name, "ceil") == 0) return native_ceil;
    if (strcmp(name, "round") == 0) return native_round;
    if (strcmp(name, "sqrt") == 0) return native_sqrt;
    if (strcmp(name, "sin") == 0) return native_sin;
    if (strcmp(name, "cos") == 0) return native_cos;
    if (strcmp(name, "tan") == 0) return native_tan;
    if (strcmp(name, "asin") == 0) return native_asin;
    if (strcmp(name, "acos") == 0) return native_acos;
    if (strcmp(name, "atan") == 0) return native_atan;
    if (strcmp(name, "log") == 0) return native_log;
    if (strcmp(name, "exp") == 0) return native_exp;
    if (strcmp(name, "slice") == 0) return native_slice;
    if (strcmp(name, "substr") == 0) return native_substr;
    if (strcmp(name, "split") == 0) return native_split;
    if (strcmp(name, "join") == 0) return native_join;
    if (strcmp(name, "upper") == 0) return native_upper;
    if (strcmp(name, "lower") == 0) return native_lower;
    if (strcmp(name, "trim") == 0) return native_trim;
    if (strcmp(name, "startsWith") == 0) return native_starts_with;
    if (strcmp(name, "endsWith") == 0) return native_ends_with;
    if (strcmp(name, "replace") == 0) return native_replace;
    if (strcmp(name, "keys") == 0) return native_keys;
    if (strcmp(name, "values") == 0) return native_values;
    if (strcmp(name, "has") == 0) return native_has;
    if (strcmp(name, "delete") == 0) return native_delete;
    if (strcmp(name, "push") == 0) return native_push;
    if (strcmp(name, "pop") == 0) return native_pop;
    if (strcmp(name, "shift") == 0) return native_shift;
    if (strcmp(name, "unshift") == 0) return native_unshift;
    if (strcmp(name, "insert") == 0) return native_insert;
    if (strcmp(name, "remove") == 0) return native_remove;
    if (strcmp(name, "find") == 0) return native_find;
    if (strcmp(name, "rfind") == 0) return native_rfind;
    if (strcmp(name, "contains") == 0) return native_contains;
    return NULL;
}
