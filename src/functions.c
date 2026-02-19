#include "vm.h"
#include "papagaio.h"
#include "papagaio_internal.h"
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DISTURB_ENABLE_FFI
void native_ffi_open(VM *vm, List *stack, List *global);
#endif

static int entry_is_string(ObjEntry *entry)
{
    return entry && entry->is_string && disturb_obj_type(entry->obj) == DISTURB_T_INT;
}

static int entry_number_scalar(ObjEntry *entry, Int *out_i, Float *out_f, int *out_is_float)
{
    if (!entry || !entry->in_use) return 0;
    Int type = disturb_obj_type(entry->obj);
    if (type == DISTURB_T_INT) {
        if (entry_is_string(entry)) return 0;
        if (disturb_bytes_len(entry->obj) != sizeof(Int)) return 0;
        Int v = 0;
        memcpy(&v, disturb_bytes_data(entry->obj), sizeof(Int));
        if (out_i) *out_i = v;
        if (out_f) *out_f = (Float)v;
        if (out_is_float) *out_is_float = 0;
        return 1;
    }
    if (type == DISTURB_T_FLOAT) {
        if (disturb_bytes_len(entry->obj) != sizeof(Float)) return 0;
        Float v = 0;
        memcpy(&v, disturb_bytes_data(entry->obj), sizeof(Float));
        if (out_i) *out_i = (Int)v;
        if (out_f) *out_f = v;
        if (out_is_float) *out_is_float = 1;
        return 1;
    }
    return 0;
}

static void write_int_bytes(List *obj, Int index, Int value)
{
    memcpy(disturb_bytes_data(obj) + (size_t)index * sizeof(Int), &value, sizeof(Int));
}

static void write_float_bytes(List *obj, Int index, Float value)
{
    memcpy(disturb_bytes_data(obj) + (size_t)index * sizeof(Float), &value, sizeof(Float));
}

static uint32_t native_argc(VM *vm, List *global)
{
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (vm && vm->argc_entry && entry_number_scalar(vm->argc_entry, &iv, &fv, &is_float) && !is_float) {
        return (uint32_t)iv;
    }
    ObjEntry *argc_entry = vm_global_find_by_key(global, "__argc");
    if (!argc_entry || !entry_number_scalar(argc_entry, &iv, &fv, &is_float) || is_float) return 0;
    return (uint32_t)iv;
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
        Int type = disturb_obj_type(self->obj);
        if (type == DISTURB_T_TABLE || type == DISTURB_T_INT || type == DISTURB_T_FLOAT) {
            return self;
        }
    }
    return native_arg(stack, argc, 0);
}

static int entry_as_number(ObjEntry *entry, Float *out)
{
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(entry, &iv, &fv, &is_float)) return 0;
    *out = is_float ? fv : (Float)iv;
    return 1;
}

static int entry_as_string(ObjEntry *entry, const char **out, size_t *len)
{
    if (!entry || !entry_is_string(entry)) return 0;
    *out = disturb_bytes_data(entry->obj);
    *len = disturb_bytes_len(entry->obj);
    return 1;
}

static List *push_entry(VM *vm, List *stack, ObjEntry *entry)
{
    List *old_stack = stack;
    stack = disturb_table_add(stack, entry);
    stack = vm_update_shared_obj(vm, old_stack, stack);
    if (vm && vm->stack_entry) vm->stack_entry->obj = stack;
    return stack;
}

static List *push_number(VM *vm, List *stack, double value)
{
    if (value >= (double)INT_MIN && value <= (double)INT_MAX) {
        Int iv = (Int)value;
        if ((double)iv == value) {
            return push_entry(vm, stack, vm_make_int_value(vm, iv));
        }
    }
    return push_entry(vm, stack, vm_make_float_value(vm, (Float)value));
}

static List *push_string(VM *vm, List *stack, const char *s, size_t len)
{
    return push_entry(vm, stack, vm_make_byte_value(vm, s, len));
}

static int number_to_int(ObjEntry *entry, Int *out);

static ObjEntry *object_find_by_key_len(List *obj, const char *name, size_t len)
{
    if (!obj || disturb_obj_type(obj) != DISTURB_T_TABLE) return NULL;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        if (!entry) continue;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || !entry_is_string(key)) continue;
        if (disturb_bytes_len(key->obj) == len &&
            memcmp(disturb_bytes_data(key->obj), name, len) == 0) {
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
    if (!number_to_int(entry, &iv)) return 0;
    if (iv < 0 || (UInt)iv > 0xFFFFFFFFu) return 0;
    *out = (uint32_t)iv;
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
        ast_err(err, err_cap, "emit expects an AST table");
        return 0;
    }
    if (disturb_obj_type(ast->obj) != DISTURB_T_TABLE) {
        ast_err(err, err_cap, "emit expects an AST table");
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
    if (!ops_entry || disturb_obj_type(ops_entry->obj) != DISTURB_T_TABLE) {
        ast_err(err, err_cap, "emit expects ops array");
        return 0;
    }

    bc_init(out);

    List *ops = ops_entry->obj;
    for (Int i = 2; i < ops->size; i++) {
        ObjEntry *op_entry = (ObjEntry*)ops->data[i].p;
        if (!op_entry || disturb_obj_type(op_entry->obj) != DISTURB_T_TABLE) {
            ast_err(err, err_cap, "emit expects op tables");
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

        if (op_len == 8 && memcmp(op_name, "PUSH_INT", 8) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!val || !entry_number_scalar(val, &iv, &fv, &is_float) || is_float) {
                ast_err(err, err_cap, "PUSH_INT expects int value");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_INT) || !bc_emit_i64(out, (int64_t)iv)) {
                ast_err(err, err_cap, "failed to emit PUSH_INT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 10 && memcmp(op_name, "PUSH_FLOAT", 10) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!val || !entry_number_scalar(val, &iv, &fv, &is_float)) {
                ast_err(err, err_cap, "PUSH_FLOAT expects value");
                bc_free(out);
                return 0;
            }
            double v = is_float ? (double)fv : (double)iv;
            if (!bc_emit_u8(out, BC_PUSH_FLOAT) || !bc_emit_f64(out, v)) {
                ast_err(err, err_cap, "failed to emit PUSH_FLOAT");
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
        } else if (op_len == 13 && memcmp(op_name, "PUSH_CHAR_RAW", 13) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen) || slen != 1) {
                ast_err(err, err_cap, "PUSH_CHAR_RAW expects single character");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_CHAR_RAW) || !bc_emit_string(out, s, slen)) {
                ast_err(err, err_cap, "failed to emit PUSH_CHAR_RAW");
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
        } else if (op_len == 15 && memcmp(op_name, "PUSH_STRING_RAW", 15) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen)) {
                ast_err(err, err_cap, "PUSH_STRING_RAW expects value");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_STRING_RAW) || !bc_emit_string(out, s, slen)) {
                ast_err(err, err_cap, "failed to emit PUSH_STRING_RAW");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 9 && memcmp(op_name, "BUILD_INT", 9) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_INT expects count");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_INT) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_INT");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 11 && memcmp(op_name, "BUILD_FLOAT", 11) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_FLOAT expects count");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_FLOAT) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_FLOAT");
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
        } else if ((op_len == 13 && memcmp(op_name, "BUILD_INT_LIT", 13) == 0) ||
                   (op_len == 15 && memcmp(op_name, "BUILD_FLOAT_LIT", 15) == 0)) {
            ObjEntry *values_entry = object_find_by_key(op_entry->obj, "values");
            if (!values_entry || disturb_obj_type(values_entry->obj) != DISTURB_T_TABLE) {
                ast_err(err, err_cap, "BUILD_*_LIT expects values");
                bc_free(out);
                return 0;
            }
            List *vals = values_entry->obj;
            uint32_t count = (uint32_t)(vals->size - 2);
            int is_float_lit = op_len == 15;
            uint8_t op_code = is_float_lit ? BC_BUILD_FLOAT_LIT : BC_BUILD_INT_LIT;
            if (!bc_emit_u8(out, op_code) || !bc_emit_u32(out, count)) {
                ast_err(err, err_cap, "failed to emit BUILD_*_LIT");
                bc_free(out);
                return 0;
            }
            for (Int j = 2; j < vals->size; j++) {
                ObjEntry *v = (ObjEntry*)vals->data[j].p;
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!v || !entry_number_scalar(v, &iv, &fv, &is_float)) {
                    ast_err(err, err_cap, "BUILD_*_LIT values must be numbers");
                    bc_free(out);
                    return 0;
                }
                if (is_float_lit) {
                    double dv = is_float ? (double)fv : (double)iv;
                    if (!bc_emit_f64(out, dv)) {
                        ast_err(err, err_cap, "failed to emit BUILD_FLOAT_LIT value");
                        bc_free(out);
                        return 0;
                    }
                } else {
                    if (is_float) {
                        ast_err(err, err_cap, "BUILD_INT_LIT expects int values");
                        bc_free(out);
                        return 0;
                    }
                    if (!bc_emit_i64(out, (int64_t)iv)) {
                        ast_err(err, err_cap, "failed to emit BUILD_INT_LIT value");
                        bc_free(out);
                        return 0;
                    }
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
            if (disturb_obj_type(args_entry->obj) != DISTURB_T_TABLE) {
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
                if (!arg || disturb_obj_type(arg->obj) != DISTURB_T_TABLE) {
                    ast_err(err, err_cap, "BUILD_FUNCTION arg must be table");
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
                if (def_entry && disturb_obj_type(def_entry->obj) != DISTURB_T_NULL) {
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
        } else if (op_len == 7 && memcmp(op_name, "CALL_EX", 7) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            ObjEntry *argc_entry = object_find_by_key(op_entry->obj, "argc");
            ObjEntry *override_entry = object_find_by_key(op_entry->obj, "override");
            const char *name = NULL;
            size_t name_len = 0;
            uint32_t argc = 0;
            uint32_t override_len = 0;
            if (!name_entry || !argc_entry || !override_entry ||
                !entry_as_string(name_entry, &name, &name_len) ||
                !entry_as_u32(argc_entry, &argc) ||
                !entry_as_u32(override_entry, &override_len)) {
                ast_err(err, err_cap, "CALL_EX expects name, argc, and override");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_CALL_EX) ||
                !bc_emit_string(out, name, name_len) ||
                !bc_emit_u32(out, argc) ||
                !bc_emit_u32(out, override_len)) {
                ast_err(err, err_cap, "failed to emit CALL_EX");
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
        } else if (op_len == 6 && memcmp(op_name, "BITAND", 6) == 0) {
            if (!bc_emit_u8(out, BC_BITAND)) {
                ast_err(err, err_cap, "failed to emit BITAND");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 5 && memcmp(op_name, "BITOR", 5) == 0) {
            if (!bc_emit_u8(out, BC_BITOR)) {
                ast_err(err, err_cap, "failed to emit BITOR");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 6 && memcmp(op_name, "BITXOR", 6) == 0) {
            if (!bc_emit_u8(out, BC_BITXOR)) {
                ast_err(err, err_cap, "failed to emit BITXOR");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "SHL", 3) == 0) {
            if (!bc_emit_u8(out, BC_SHL)) {
                ast_err(err, err_cap, "failed to emit SHL");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "SHR", 3) == 0) {
            if (!bc_emit_u8(out, BC_SHR)) {
                ast_err(err, err_cap, "failed to emit SHR");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 3 && memcmp(op_name, "NEG", 3) == 0) {
            if (!bc_emit_u8(out, BC_NEG)) {
                ast_err(err, err_cap, "failed to emit NEG");
                bc_free(out);
                return 0;
            }
        } else if (op_len == 4 && memcmp(op_name, "BNOT", 4) == 0) {
            if (!bc_emit_u8(out, BC_BNOT)) {
                ast_err(err, err_cap, "failed to emit BNOT");
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
    if (!vm || !ast || disturb_obj_type(ast->obj) != DISTURB_T_TABLE) {
        ast_err(err, err_cap, "astToSource expects AST object");
        return 0;
    }
    ObjEntry *ops_entry = object_find_by_key(ast->obj, "ops");
    if (!ops_entry || disturb_obj_type(ops_entry->obj) != DISTURB_T_TABLE) {
        ast_err(err, err_cap, "astToSource expects ops array");
        return 0;
    }
    List *ops = ops_entry->obj;
    for (Int i = 2; i < ops->size; i++) {
        ObjEntry *op_entry = (ObjEntry*)ops->data[i].p;
        if (!op_entry || disturb_obj_type(op_entry->obj) != DISTURB_T_TABLE) {
            ast_err(err, err_cap, "astToSource expects op objects");
            return 0;
        }
        ObjEntry *op_name_entry = object_find_by_key(op_entry->obj, "op");
        const char *op_name = NULL;
        size_t op_len = 0;
        if (!op_name_entry || !entry_as_string(op_name_entry, &op_name, &op_len)) {
            ast_err(err, err_cap, "astToSource expects op name");
            return 0;
        }
        sb_append_n(out, op_name, op_len);

        if (op_len == 8 && memcmp(op_name, "PUSH_INT", 8) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!val || !entry_number_scalar(val, &iv, &fv, &is_float) || is_float) {
                ast_err(err, err_cap, "PUSH_INT expects int value");
                return 0;
            }
            char buf[64];
            snprintf(buf, sizeof(buf), " %lld", (long long)iv);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 10 && memcmp(op_name, "PUSH_FLOAT", 10) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!val || !entry_number_scalar(val, &iv, &fv, &is_float)) {
                ast_err(err, err_cap, "PUSH_FLOAT expects value");
                return 0;
            }
            double v = is_float ? (double)fv : (double)iv;
            char buf[64];
            snprintf(buf, sizeof(buf), " %.17g", v);
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
        } else if (op_len == 13 && memcmp(op_name, "PUSH_CHAR_RAW", 13) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen) || slen != 1) {
                ast_err(err, err_cap, "PUSH_CHAR_RAW expects single character");
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
        } else if (op_len == 15 && memcmp(op_name, "PUSH_STRING_RAW", 15) == 0) {
            ObjEntry *val = object_find_by_key(op_entry->obj, "value");
            const char *s = NULL;
            size_t slen = 0;
            if (!val || !entry_as_string(val, &s, &slen)) {
                ast_err(err, err_cap, "PUSH_STRING_RAW expects value");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_escaped(out, s, slen, '"');
        } else if (op_len == 9 && memcmp(op_name, "BUILD_INT", 9) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_INT expects count");
                return 0;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), " %u", (unsigned)count);
            sb_append_n(out, buf, strlen(buf));
        } else if (op_len == 11 && memcmp(op_name, "BUILD_FLOAT", 11) == 0) {
            ObjEntry *count_entry = object_find_by_key(op_entry->obj, "count");
            uint32_t count = 0;
            if (!count_entry || !entry_as_u32(count_entry, &count)) {
                ast_err(err, err_cap, "BUILD_FLOAT expects count");
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
        } else if ((op_len == 13 && memcmp(op_name, "BUILD_INT_LIT", 13) == 0) ||
                   (op_len == 15 && memcmp(op_name, "BUILD_FLOAT_LIT", 15) == 0)) {
            ObjEntry *values_entry = object_find_by_key(op_entry->obj, "values");
            if (!values_entry || disturb_obj_type(values_entry->obj) != DISTURB_T_TABLE) {
                ast_err(err, err_cap, "BUILD_*_LIT expects values");
                return 0;
            }
            List *vals = values_entry->obj;
            uint32_t count = (uint32_t)(vals->size - 2);
            char buf[32];
            int is_float_lit = op_len == 15;
            snprintf(buf, sizeof(buf), " %u", (unsigned)count);
            sb_append_n(out, buf, strlen(buf));
            for (Int j = 2; j < vals->size; j++) {
                ObjEntry *v = (ObjEntry*)vals->data[j].p;
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!v || !entry_number_scalar(v, &iv, &fv, &is_float)) {
                    ast_err(err, err_cap, "BUILD_*_LIT values must be numbers");
                    return 0;
                }
                char num_buf[64];
                if (is_float_lit) {
                    double dv = is_float ? (double)fv : (double)iv;
                    snprintf(num_buf, sizeof(num_buf), " %.17g", dv);
                } else {
                    if (is_float) {
                        ast_err(err, err_cap, "BUILD_INT_LIT expects int values");
                        return 0;
                    }
                    snprintf(num_buf, sizeof(num_buf), " %lld", (long long)iv);
                }
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

            if (disturb_obj_type(args_entry->obj) != DISTURB_T_TABLE) {
                ast_err(err, err_cap, "BUILD_FUNCTION expects args array");
                return 0;
            }
            List *args = args_entry->obj;
            for (uint32_t j = 0; j < argc; j++) {
                ObjEntry *arg = (ObjEntry*)args->data[2 + j].p;
                if (!arg || disturb_obj_type(arg->obj) != DISTURB_T_TABLE) {
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
                if (def_entry && disturb_obj_type(def_entry->obj) != DISTURB_T_NULL) {
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
        } else if (op_len == 6 && memcmp(op_name, "STRICT", 6) == 0) {
            // no args
        } else if (op_len == 8 && memcmp(op_name, "UNSTRICT", 8) == 0) {
            // no args
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
        } else if (op_len == 7 && memcmp(op_name, "CALL_EX", 7) == 0) {
            ObjEntry *name_entry = object_find_by_key(op_entry->obj, "name");
            ObjEntry *argc_entry = object_find_by_key(op_entry->obj, "argc");
            ObjEntry *override_entry = object_find_by_key(op_entry->obj, "override");
            const char *name = NULL;
            size_t name_len = 0;
            uint32_t argc = 0;
            uint32_t override_len = 0;
            if (!name_entry || !argc_entry || !override_entry ||
                !entry_as_string(name_entry, &name, &name_len) ||
                !entry_as_u32(argc_entry, &argc) ||
                !entry_as_u32(override_entry, &override_len)) {
                ast_err(err, err_cap, "CALL_EX expects name, argc, and override");
                return 0;
            }
            sb_append_char(out, ' ');
            sb_append_n(out, name, name_len);
            char buf[64];
            snprintf(buf, sizeof(buf), " %u %u", (unsigned)argc, (unsigned)override_len);
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

static int ends_with_script_ext(const char *s, size_t len)
{
    static const char ext[] = ".urb";
    size_t ext_len = sizeof(ext) - 1;
    if (len < ext_len) return 0;
    return memcmp(s + (len - ext_len), ext, ext_len) == 0;
}

#ifndef DISTURB_EMBEDDED
static char *module_resolve_path(const char *path, size_t path_len, size_t *out_len)
{
    if (!path || path_len == 0) return NULL;

    size_t len = path_len;
    while (len > 0 && (path[len - 1] == '/' || path[len - 1] == '\\')) len--;
    if (len == 0) return NULL;

    if (ends_with_script_ext(path, len)) {
        char *out = (char*)malloc(len + 1);
        if (!out) return NULL;
        memcpy(out, path, len);
        out[len] = 0;
        if (out_len) *out_len = len;
        return out;
    }

    size_t base_start = 0;
    for (size_t i = len; i > 0; i--) {
        char c = path[i - 1];
        if (c == '/' || c == '\\') {
            base_start = i;
            break;
        }
    }
    size_t base_len = len - base_start;
    if (base_len == 0) return NULL;

    size_t out_size = len + 1 + base_len + (sizeof(".urb") - 1);
    char *out = (char*)malloc(out_size + 1);
    if (!out) return NULL;
    size_t at = 0;
    memcpy(out + at, path, len);
    at += len;
    out[at++] = '/';
    memcpy(out + at, path + base_start, base_len);
    at += base_len;
    memcpy(out + at, ".urb", sizeof(".urb") - 1);
    at += sizeof(".urb") - 1;
    out[at] = 0;
    if (out_len) *out_len = at;
    return out;
}

static ObjEntry *module_cache_get(VM *vm, List *global, const char *path, size_t path_len)
{
    (void)vm;
    ObjEntry *cache = vm_global_find_by_key(global, "__modules");
    if (!cache || disturb_obj_type(cache->obj) != DISTURB_T_TABLE) return NULL;
    return object_find_by_key_len(cache->obj, path, path_len);
}

static ObjEntry *module_cache_ensure(VM *vm, List *global)
{
    ObjEntry *cache = vm_global_find_by_key(global, "__modules");
    if (cache && disturb_obj_type(cache->obj) == DISTURB_T_TABLE) return cache;
    cache = vm_make_table_value(vm, 8);
    if (!cache) return NULL;
    if (!vm_object_set_by_key(vm, vm->global_entry, "__modules", 9, cache)) return NULL;
    return vm_global_find_by_key(global, "__modules");
}

static void native_import(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    const char *raw_path = NULL;
    size_t raw_len = 0;
    if (!entry_as_string(arg0, &raw_path, &raw_len)) {
        fprintf(stderr, "import expects string path\n");
        return;
    }

    size_t resolved_len = 0;
    char *resolved = module_resolve_path(raw_path, raw_len, &resolved_len);
    if (!resolved) {
        fprintf(stderr, "import failed: invalid module path\n");
        return;
    }

    ObjEntry *cached = module_cache_get(vm, global, resolved, resolved_len);
    if (cached) {
        push_entry(vm, stack, cached);
        free(resolved);
        return;
    }

    size_t src_len = 0;
    char *src = read_file_bytes(resolved, &src_len);
    if (!src && src_len == 0) {
        fprintf(stderr, "import failed: could not read '%s'\n", resolved);
        free(resolved);
        return;
    }

    VM module_vm;
    vm_init(&module_vm);
    ObjEntry *ret = vm_eval_source(&module_vm, src ? src : "", src_len);
    if (!ret) ret = module_vm.null_entry;

    ObjEntry *exported = NULL;
    if (ret == module_vm.null_entry || disturb_obj_type(ret->obj) == DISTURB_T_NULL) {
        exported = vm->null_entry;
    } else {
        exported = vm_clone_entry_deep(vm, ret, NULL);
    }

    vm_free(&module_vm);
    free(src);

    if (!exported) {
        fprintf(stderr, "import failed: could not clone module export\n");
        free(resolved);
        return;
    }

    ObjEntry *cache = module_cache_ensure(vm, global);
    if (!cache || !vm_object_set_by_key(vm, cache, resolved, resolved_len, exported)) {
        fprintf(stderr, "import failed: cache set failed\n");
        free(resolved);
        return;
    }

    ObjEntry *stored = module_cache_get(vm, global, resolved, resolved_len);
    push_entry(vm, stack, stored ? stored : exported);
    free(resolved);
}
#endif

static void native_print(VM *vm, List *stack, List *global)
{
    (void)vm;
    (void)global;
    uint32_t argc = native_argc(vm, global);
    if (argc == 0) {
        if (stack->size > 2) {
            ObjEntry *entry = (ObjEntry*)stack->data[stack->size - 1].p;
            print_plain_entry(stdout, vm, entry);
            return;
        }
        fputs("(stack empty)", stdout);
        return;
    }
    for (uint32_t i = 0; i < argc; i++) {
        ObjEntry *entry = native_arg(stack, argc, i);
        if (i) fputc(' ', stdout);
        print_entry(stdout, vm, entry);
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
            print_plain_entry(stdout, vm, entry);
        }
        fputc('\n', stdout);
        return;
    }
    for (uint32_t i = 0; i < argc; i++) {
        ObjEntry *entry = native_arg(stack, argc, i);
        if (i) fputc(' ', stdout);
        print_plain_entry(stdout, vm, entry);
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
    Int length = vm_value_len_entry(target);
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
    stack = push_entry(vm, stack, out);
}

static void native_clone(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "clone expects a value\n");
        return;
    }
    ObjEntry *out = vm_clone_entry_shallow_copy(vm, target, NULL);
    if (!out) return;
    stack = push_entry(vm, stack, out);
}

static void native_copy(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "copy expects a value\n");
        return;
    }
    ObjEntry *out = vm_clone_entry_deep(vm, target, NULL);
    if (!out) return;
    stack = push_entry(vm, stack, out);
}

static void native_to_int(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target || disturb_obj_type(target->obj) != DISTURB_T_FLOAT) {
        fprintf(stderr, "toInt expects a float list\n");
        return;
    }
    Int count = vm_value_len_entry(target);
    ObjEntry *entry = vm_make_int_list(vm, count);
    if (!entry) return;
    List *obj = entry->obj;
    for (Int i = 0; i < count; i++) {
        Float v = 0;
        memcpy(&v, disturb_bytes_data(target->obj) + (size_t)i * sizeof(Float), sizeof(Float));
        write_int_bytes(obj, i, (Int)v);
    }
    stack = push_entry(vm, stack, entry);
}

static void native_to_float(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target || disturb_obj_type(target->obj) != DISTURB_T_INT) {
        fprintf(stderr, "toFloat expects an int list\n");
        return;
    }
    size_t bytes_len = disturb_bytes_len(target->obj);
    Int count = entry_is_string(target) ? (Int)bytes_len : (Int)(bytes_len / sizeof(Int));
    ObjEntry *entry = vm_make_float_list(vm, count);
    if (!entry) return;
    List *obj = entry->obj;
    if (entry_is_string(target)) {
        for (Int i = 0; i < count; i++) {
            unsigned char b = (unsigned char)disturb_bytes_data(target->obj)[i];
            Float v = (Float)b;
            write_float_bytes(obj, i, v);
        }
    } else {
        for (Int i = 0; i < count; i++) {
            Int v = 0;
            memcpy(&v, disturb_bytes_data(target->obj) + (size_t)i * sizeof(Int), sizeof(Int));
            write_float_bytes(obj, i, (Float)v);
        }
    }
    stack = push_entry(vm, stack, entry);
}

#ifdef DISTURB_ENABLE_IO
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
        stack = push_entry(vm, stack, vm->null_entry);
        return;
    }
    ObjEntry *out = vm_make_byte_value(vm, data ? data : "", len);
    free(data);
    stack = push_entry(vm, stack, out);
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
        data = disturb_bytes_data(string_entry->obj);
        data_len = disturb_bytes_len(string_entry->obj);
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
#endif

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
    stack = push_entry(vm, stack, vm->null_entry);
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
    if (!vm_compile_source_with_vm(vm, buf, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "parse error");
        free(buf);
        return;
    }
    free(buf);
    ObjEntry *bytes = vm_make_byte_value(vm, (const char*)bc.data, bc.len);
    bc_free(&bc);
    stack = push_entry(vm, stack, bytes);
}

static void native_emit(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    const char *data = NULL;
    size_t len = 0;
    if (entry_as_string(target, &data, &len)) {
        ObjEntry *ast = vm_bytecode_to_ast(vm, (const unsigned char*)data, len);
        if (!ast) {
            fprintf(stderr, "emit failed to decode bytecode\n");
            return;
        }
        StrBuf out;
        sb_init(&out);
        char err[256];
        err[0] = 0;
        if (!ast_to_source(vm, ast, &out, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err[0] ? err : "emit failed");
            sb_free(&out);
            return;
        }
        push_string(vm, stack, out.data, out.len);
        sb_free(&out);
        return;
    }

    if (target && target->obj && disturb_obj_type(target->obj) == DISTURB_T_TABLE) {
        Bytecode bc;
        char err[256];
        err[0] = 0;
        if (!ast_to_bytecode(vm, target, &bc, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err[0] ? err : "emit failed");
            return;
        }
        ObjEntry *bytes = vm_make_byte_value(vm, (const char*)bc.data, bc.len);
        bc_free(&bc);
        stack = push_entry(vm, stack, bytes);
        return;
    }

    fprintf(stderr, "emit expects bytecode bytes\n");
}

static void native_bytecode_to_ast(VM *vm, List *stack, List *global)
{
    (void)global;
    stack = push_entry(vm, stack, vm->null_entry);
}

static void native_ast_to_source(VM *vm, List *stack, List *global)
{
    (void)global;
    stack = push_entry(vm, stack, vm->null_entry);
}

static void native_eval_bytecode(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    const char *data = NULL;
    size_t len = 0;
    if (!entry_as_string(target, &data, &len)) {
        fprintf(stderr, "evalBytecode expects byte/string data\n");
        return;
    }
    vm_exec_bytecode(vm, (const unsigned char*)data, len);
    stack = push_entry(vm, stack, vm->null_entry);
}

static void native_gc_collect(VM *vm, List *stack, List *global)
{
    (void)global;
    if (vm) vm_gc(vm);
    if (vm) {
        stack = push_entry(vm, stack, vm->null_entry);
    }
}

static int gc_entry_protected(VM *vm, ObjEntry *entry)
{
    if (!vm || !entry) return 1;
    return entry == vm->global_entry || entry == vm->stack_entry || entry == vm->null_entry ||
           entry == vm->common_entry || entry == vm->gc_entry || entry == vm->argc_entry;
}

static int gc_entry_shared(VM *vm, ObjEntry *entry)
{
    if (!vm || !entry || !entry->obj) return 0;
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *other = vm->reg[i];
        if (!other || !other->in_use || other == entry) continue;
        if (other->obj == entry->obj) return 1;
    }
    return 0;
}

static void native_gc_free(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_arg(stack, argc, 0);
    if (!target) {
        fprintf(stderr, "gc.free expects a value\n");
        return;
    }
    if (gc_entry_protected(vm, target)) {
        fprintf(stderr, "gc.free cannot free protected values\n");
        return;
    }
    if (gc_entry_shared(vm, target)) {
        fprintf(stderr, "gc.free cannot free shared values\n");
        return;
    }
    ObjEntry *key_entry = vm_entry_key(target);
    if (target->obj) {
        vm_free_list(vm, target->obj);
    }
    target->obj = vm_alloc_list(vm, DISTURB_T_NULL, key_entry, 0);
    target->key = key_entry;
    target->mark = 0;
    push_number(vm, stack, 1);
}

static void native_gc_sweep(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_arg(stack, argc, 0);
    if (!target) {
        fprintf(stderr, "gc.sweep expects a value\n");
        return;
    }
    if (gc_entry_protected(vm, target)) {
        fprintf(stderr, "gc.sweep cannot sweep protected values\n");
        return;
    }
    ObjEntry *key_entry = vm_entry_key(target);
    if (target->obj && !gc_entry_shared(vm, target)) {
        vm_reuse_list(vm, target->obj);
    }
    target->obj = vm_alloc_list(vm, DISTURB_T_NULL, key_entry, 0);
    target->key = key_entry;
    target->mark = 0;
    push_number(vm, stack, 1);
}

static void native_gc_new(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = native_argc(vm, global);
    Int size = 0;
    if (argc >= 1) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!number_to_int(arg0, &size) || size < 0) {
            fprintf(stderr, "gc.new expects non-negative size\n");
            return;
        }
    }
    ObjEntry *entry = vm_make_table_value(vm, size);
    if (!entry) return;
    stack = push_entry(vm, stack, entry);
}

static void native_gc_flush(VM *vm, List *stack, List *global)
{
    (void)global;
    if (vm) vm_flush_reuse(vm);
    if (vm) {
        stack = push_entry(vm, stack, vm->null_entry);
    }
}

static void native_gc_debug(VM *vm, List *stack, List *global)
{
    (void)global;
    size_t total_bytes = 0;
    size_t list_count = 0;
    size_t bytes_count = 0;

    fputs("gc.reuse.lists:\n", stdout);
    if (vm) {
        FreeNode *cur = vm->free_list_objs;
        while (cur) {
            size_t bytes = sizeof(List);
            fprintf(stdout, "  bytes=%zu\n", bytes);
            total_bytes += bytes;
            list_count++;
            cur = cur->next;
        }
    }

    fputs("gc.reuse.data:\n", stdout);
    if (vm) {
        FreeDataNode *cur = vm->free_list_data;
        while (cur) {
            size_t bytes = cur->cap_bytes;
            fprintf(stdout, "  cap_bytes=%zu\n", cur->cap_bytes);
            total_bytes += bytes;
            bytes_count++;
            cur = cur->next;
        }
    }

    fprintf(stdout, "gc.reuse.total: lists=%zu bytes=%zu total_bytes=%zu\n",
            list_count, bytes_count, total_bytes);
    if (vm) {
        stack = push_entry(vm, stack, vm->null_entry);
    }
}

static void native_gc_stats(VM *vm, List *stack, List *global)
{
    (void)global;
    GcStats stats;
    if (!vm || !vm_gc_stats(vm, &stats)) {
        fprintf(stderr, "gc.stats failed\n");
        return;
    }
    fprintf(stdout, "gc.stats.reuse: lists=%zu bytes=%zu total_bytes=%zu\n",
            stats.reuse_list_count, stats.reuse_bytes_count, stats.reuse_bytes_total);
    fprintf(stdout, "gc.stats.inuse: count=%zu bytes=%zu\n",
            stats.inuse_count, stats.inuse_bytes);
    fprintf(stdout, "gc.stats.noref: count=%zu bytes=%zu\n",
            stats.noref_count, stats.noref_bytes);
    fprintf(stdout, "gc.stats.total: bytes=%zu\n", stats.total_bytes);
    stack = push_entry(vm, stack, vm->null_entry);
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

    if (!entry_is_string(dst) || !entry_is_string(src)) {
        fprintf(stderr, "append expects string values\n");
        return;
    }

    dst->obj = vm_update_shared_obj(vm, dst->obj,
                                    disturb_bytes_append(dst->obj,
                                                     disturb_bytes_data(src->obj),
                                                     disturb_bytes_len(src->obj)));
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
    if (self && entry_is_string(self)) return self;
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    if (arg0 && entry_is_string(arg0)) return arg0;
    return NULL;
}

static int number_to_int(ObjEntry *entry, Int *out)
{
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(entry, &iv, &fv, &is_float)) return 0;
    if (is_float) {
        Int cast = (Int)fv;
        if ((Float)cast != fv) return 0;
        iv = cast;
    }
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

static Int bytes_list_count(const ObjEntry *entry, size_t elem_size)
{
    size_t len = disturb_bytes_len(entry->obj);
    if (elem_size == 0) return 0;
    return (Int)(len / elem_size);
}

static int bytes_list_index(Int count, Int index, Int *out_index)
{
    if (index < 0) index = count + index;
    if (index < 0 || index >= count) return 0;
    *out_index = index;
    return 1;
}

static Int bytes_list_insert_index(Int count, Int index)
{
    if (index < 0) index = count + index;
    if (index < 0) return 0;
    if (index > count) return count;
    return index;
}

static List *bytes_list_insert(VM *vm, ObjEntry *target, size_t offset, const void *data, size_t len)
{
    (void)vm;
    size_t old_len = disturb_bytes_len(target->obj);
    size_t new_len = old_len + len;
    size_t bytes = 2 * sizeof(Value) + new_len;
    Value *next = (Value*)realloc(target->obj->data, bytes);
    if (!next && bytes > 0) return NULL;
    if (next) target->obj->data = next;
    List *obj = target->obj;
    memmove(disturb_bytes_data(obj) + offset + len, disturb_bytes_data(obj) + offset, old_len - offset);
    memcpy(disturb_bytes_data(obj) + offset, data, len);
    obj->size = (UHalf)(new_len + 2);
    obj->capacity = obj->size;
    target->obj = obj;
    return obj;
}

static int bytes_list_remove(VM *vm, ObjEntry *target, size_t offset, void *out, size_t len)
{
    (void)vm;
    size_t old_len = disturb_bytes_len(target->obj);
    if (offset + len > old_len) return 0;
    if (out) memcpy(out, disturb_bytes_data(target->obj) + offset, len);
    memmove(disturb_bytes_data(target->obj) + offset,
            disturb_bytes_data(target->obj) + offset + len,
            old_len - offset - len);
    size_t new_len = old_len - len;
    target->obj->size = (UHalf)(new_len + 2);
    target->obj->capacity = target->obj->size;
    return 1;
}

static void native_slice(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "slice expects a string target\n");
        return;
    }
    const char *s = disturb_bytes_data(target->obj);
    size_t len = disturb_bytes_len(target->obj);
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
    const char *s = disturb_bytes_data(target->obj);
    size_t len = disturb_bytes_len(target->obj);
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
    size_t len = disturb_bytes_len(target->obj);
    char *buf = (char*)malloc(len);
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)toupper((unsigned char)disturb_bytes_data(target->obj)[i]);
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
    size_t len = disturb_bytes_len(target->obj);
    char *buf = (char*)malloc(len);
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)tolower((unsigned char)disturb_bytes_data(target->obj)[i]);
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
    const char *s = disturb_bytes_data(target->obj);
    size_t len = disturb_bytes_len(target->obj);
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
    const char *s = disturb_bytes_data(target->obj);
    size_t len = disturb_bytes_len(target->obj);
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
    const char *s = disturb_bytes_data(target->obj);
    size_t len = disturb_bytes_len(target->obj);
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
    const char *s = disturb_bytes_data(target->obj);
    size_t len = disturb_bytes_len(target->obj);
    const char *delim = "";
    size_t dlen = 0;
    if (argc >= 1) {
        ObjEntry *arg0 = native_arg(stack, argc, 0);
        if (!entry_as_string(arg0, &delim, &dlen)) {
            fprintf(stderr, "split expects a string delimiter\n");
            return;
        }
    }

    ObjEntry *out = vm_make_table_value(vm, 8);
    if (dlen == 0) {
        for (size_t i = 0; i < len; i++) {
            ObjEntry *part = vm_make_byte_value(vm, s + i, 1);
            out->obj = disturb_table_add(out->obj, part);
        }
        stack = push_entry(vm, stack, out);
        return;
    }

    size_t pos = 0;
    while (pos <= len) {
        size_t next = pos;
        while (next + dlen <= len && memcmp(s + next, delim, dlen) != 0) next++;
        ObjEntry *part = vm_make_byte_value(vm, s + pos, next - pos);
        out->obj = disturb_table_add(out->obj, part);
        pos = next + dlen;
        if (next + dlen > len) break;
    }
    stack = push_entry(vm, stack, out);
}

static void native_join(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_target(vm, stack, argc);
    if (!target || disturb_obj_type(target->obj) != DISTURB_T_TABLE) {
        fprintf(stderr, "join expects a table/array target\n");
        return;
    }
    const char *delim = "";
    size_t dlen = 0;
    ObjEntry *arg0 = native_arg(stack, argc, 0);
    if (arg0 && entry_is_string(arg0)) {
        delim = disturb_bytes_data(arg0->obj);
        dlen = disturb_bytes_len(arg0->obj);
    }

    StrBuf buf;
    sb_init(&buf);
    for (Int i = 2; i < target->obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)target->obj->data[i].p;
        if (i > 2 && dlen) sb_append_n(&buf, delim, dlen);
        ObjEntry *str = vm_stringify_value(vm, entry, 1);
        sb_append_n(&buf, disturb_bytes_data(str->obj), disturb_bytes_len(str->obj));
    }
    push_string(vm, stack, buf.data, buf.len);
    sb_free(&buf);
}

static size_t find_substring(const char *hay, size_t hlen, const char *needle, size_t nlen, size_t start)
{
    if (nlen == 0 || nlen > hlen || start > hlen - nlen) return SIZE_MAX;
    for (size_t i = start; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return i;
    }
    return SIZE_MAX;
}

static void native_replace_impl(VM *vm, List *stack, List *global, int replace_all, const char *name)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "%s expects a string target\n", name);
        return;
    }
    if (argc < 2) {
        fprintf(stderr, "%s expects needle and replacement\n", name);
        return;
    }

    ObjEntry *arg0 = native_arg(stack, argc, 0);
    ObjEntry *arg1 = native_arg(stack, argc, 1);
    const char *needle = NULL;
    size_t nlen = 0;
    const char *repl = NULL;
    size_t rlen = 0;
    if (!entry_as_string(arg0, &needle, &nlen) || !entry_as_string(arg1, &repl, &rlen)) {
        fprintf(stderr, "%s expects string needle and replacement\n", name);
        return;
    }

    const char *hay = disturb_bytes_data(target->obj);
    size_t hlen = disturb_bytes_len(target->obj);
    if (nlen == 0 || hlen == 0) {
        push_string(vm, stack, hay, hlen);
        return;
    }

    size_t first = find_substring(hay, hlen, needle, nlen, 0);
    if (first == SIZE_MAX) {
        push_string(vm, stack, hay, hlen);
        return;
    }

    StrBuf out;
    sb_init(&out);
    if (!replace_all) {
        sb_append_n(&out, hay, first);
        sb_append_n(&out, repl, rlen);
        sb_append_n(&out, hay + first + nlen, hlen - (first + nlen));
        push_string(vm, stack, out.data, out.len);
        sb_free(&out);
        return;
    }

    size_t pos = 0;
    size_t match = first;
    while (match != SIZE_MAX) {
        sb_append_n(&out, hay + pos, match - pos);
        sb_append_n(&out, repl, rlen);
        pos = match + nlen;
        match = find_substring(hay, hlen, needle, nlen, pos);
    }
    sb_append_n(&out, hay + pos, hlen - pos);
    push_string(vm, stack, out.data, out.len);
    sb_free(&out);
}

static void native_replace(VM *vm, List *stack, List *global)
{
    native_replace_impl(vm, stack, global, 0, "replace");
}

static void native_replace_all(VM *vm, List *stack, List *global)
{
    native_replace_impl(vm, stack, global, 1, "replaceAll");
}

static void native_papagaio(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "papagaio expects a string target\n");
        return;
    }
    const char *input = disturb_bytes_data(target->obj);
    size_t input_len = disturb_bytes_len(target->obj);
    char *out = papagaio_process_text(vm, input, input_len);
    if (!out) {
        fprintf(stderr, "papagaio failed\n");
        return;
    }
    push_string(vm, stack, out, strlen(out));
    free(out);
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

    const char *hay = disturb_bytes_data(target->obj);
    size_t hlen_sz = disturb_bytes_len(target->obj);
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

    const char *hay = disturb_bytes_data(target->obj);
    size_t hlen_sz = disturb_bytes_len(target->obj);
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

    const char *hay = disturb_bytes_data(target->obj);
    size_t hlen = disturb_bytes_len(target->obj);
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
    if (!target || disturb_obj_type(target->obj) != DISTURB_T_TABLE) return NULL;
    return target;
}

static void native_keys(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_object_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "keys expects table target\n");
        return;
    }
    ObjEntry *out = vm_make_table_value(vm, target->obj->size - 2);
    for (Int i = 2; i < target->obj->size; i++) {
        ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
        ObjEntry *key = vm_entry_key(child);
        if (!key || !entry_is_string(key)) continue;
        ObjEntry *entry = vm_make_byte_value(vm, disturb_bytes_data(key->obj), disturb_bytes_len(key->obj));
        out->obj = disturb_table_add(out->obj, entry);
    }
    stack = push_entry(vm, stack, out);
}

static void native_values(VM *vm, List *stack, List *global)
{
    uint32_t argc = native_argc(vm, global);
    ObjEntry *target = native_object_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "values expects table target\n");
        return;
    }
    ObjEntry *out = vm_make_table_value(vm, target->obj->size - 2);
    for (Int i = 2; i < target->obj->size; i++) {
        ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
        if (!child) continue;
        out->obj = disturb_table_add(out->obj, child);
    }
    stack = push_entry(vm, stack, out);
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

    Int type = disturb_obj_type(target->obj);
    if (entry_is_string(idx) && type == DISTURB_T_TABLE) {
        const char *key = disturb_bytes_data(idx->obj);
        size_t len = disturb_bytes_len(idx->obj);
        for (Int i = 2; i < target->obj->size; i++) {
            ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
            ObjEntry *k = vm_entry_key(child);
            if (!k || !entry_is_string(k)) continue;
            if (disturb_bytes_len(k->obj) == len && memcmp(disturb_bytes_data(k->obj), key, len) == 0) {
                push_number(vm, stack, 1);
                return;
            }
        }
        push_number(vm, stack, 0);
        return;
    }

    if (disturb_obj_type(idx->obj) == DISTURB_T_INT || disturb_obj_type(idx->obj) == DISTURB_T_FLOAT) {
        Int i = 0;
        if (!number_to_int(idx, &i)) {
            fprintf(stderr, "has expects integer index\n");
            return;
        }
        Int size = vm_value_len_entry(target);
        if (i < 0) i = size + i;
        if (i < 0 || i >= size) {
            push_number(vm, stack, 0);
            return;
        }
        push_number(vm, stack, 1);
        return;
    }

    fprintf(stderr, "has expects table key or numeric index\n");
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

    Int type = disturb_obj_type(target->obj);
    if (entry_is_string(idx) && type == DISTURB_T_TABLE) {
        const char *key = disturb_bytes_data(idx->obj);
        size_t len = disturb_bytes_len(idx->obj);
        for (Int i = 2; i < target->obj->size; i++) {
            ObjEntry *child = (ObjEntry*)target->obj->data[i].p;
            ObjEntry *k = vm_entry_key(child);
            if (!k || !entry_is_string(k)) continue;
            if (disturb_bytes_len(k->obj) == len && memcmp(disturb_bytes_data(k->obj), key, len) == 0) {
                urb_remove(target->obj, i);
                push_number(vm, stack, 1);
                return;
            }
        }
        push_number(vm, stack, 0);
        return;
    }

    if (disturb_obj_type(idx->obj) == DISTURB_T_INT || disturb_obj_type(idx->obj) == DISTURB_T_FLOAT) {
        Int i = 0;
        if (!number_to_int(idx, &i)) {
            fprintf(stderr, "delete expects integer index\n");
            return;
        }
        if (!list_index_valid(target->obj, i)) {
            push_number(vm, stack, 0);
            return;
        }
        if (type == DISTURB_T_TABLE) {
            urb_remove(target->obj, list_pos_from_index(target->obj, i));
            push_number(vm, stack, 1);
            return;
        }
        if (type == DISTURB_T_INT) {
            Int count = bytes_list_count(target, entry_is_string(target) ? 1 : sizeof(Int));
            Int pos = 0;
            if (!bytes_list_index(count, i, &pos)) {
                push_number(vm, stack, 0);
                return;
            }
            if (entry_is_string(target)) {
                bytes_list_remove(vm, target, (size_t)pos, NULL, 1);
            } else {
                bytes_list_remove(vm, target, (size_t)pos * sizeof(Int), NULL, sizeof(Int));
            }
            push_number(vm, stack, 1);
            return;
        }
        if (type == DISTURB_T_FLOAT) {
            Int count = bytes_list_count(target, sizeof(Float));
            Int pos = 0;
            if (!bytes_list_index(count, i, &pos)) {
                push_number(vm, stack, 0);
                return;
            }
            bytes_list_remove(vm, target, (size_t)pos * sizeof(Float), NULL, sizeof(Float));
            push_number(vm, stack, 1);
            return;
        }
    }

    fprintf(stderr, "delete expects table key or numeric index\n");
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
    Int type = disturb_obj_type(target->obj);
    for (uint32_t i = start; i < argc; i++) {
        ObjEntry *arg = native_arg(stack, argc, i);
        if (!arg) continue;
        if (type == DISTURB_T_TABLE) {
            target->obj = vm_update_shared_obj(vm, target->obj,
                                               disturb_table_add(target->obj, arg));
        } else if (type == DISTURB_T_INT && entry_is_string(target)) {
            if (!entry_is_string(arg)) {
                fprintf(stderr, "push expects string values\n");
                return;
            }
            target->obj = vm_update_shared_obj(vm, target->obj,
                                               disturb_bytes_append(target->obj,
                                                                disturb_bytes_data(arg->obj),
                                                                disturb_bytes_len(arg->obj)));
        } else if (type == DISTURB_T_INT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number_scalar(arg, &iv, &fv, &is_float)) {
                fprintf(stderr, "push expects number values\n");
                return;
            }
            if (is_float) {
                Int cast = (Int)fv;
                if ((Float)cast != fv) {
                    fprintf(stderr, "push expects int values\n");
                    return;
                }
                iv = cast;
            }
            size_t offset = disturb_bytes_len(target->obj);
            if (!bytes_list_insert(vm, target, offset, &iv, sizeof(Int))) {
                fprintf(stderr, "push failed to grow list\n");
                return;
            }
        } else if (type == DISTURB_T_FLOAT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number_scalar(arg, &iv, &fv, &is_float)) {
                fprintf(stderr, "push expects number values\n");
                return;
            }
            Float out = is_float ? fv : (Float)iv;
            size_t offset = disturb_bytes_len(target->obj);
            if (!bytes_list_insert(vm, target, offset, &out, sizeof(Float))) {
                fprintf(stderr, "push failed to grow list\n");
                return;
            }
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
    Int type = disturb_obj_type(target->obj);
    if (type == DISTURB_T_TABLE) {
        if (target->obj->size <= 2) return;
        Value v = urb_pop(target->obj);
        ObjEntry *entry = (ObjEntry*)v.p;
        if (entry) {
            stack = push_entry(vm, stack, entry);
        }
        return;
    }
    if (type == DISTURB_T_INT && entry_is_string(target)) {
        size_t len = disturb_bytes_len(target->obj);
        if (!len) return;
        char c = disturb_bytes_data(target->obj)[len - 1];
        target->obj->size = (UHalf)(len - 1 + 2);
        target->obj->capacity = target->obj->size;
        push_string(vm, stack, &c, 1);
        return;
    }
    if (type == DISTURB_T_INT) {
        Int count = bytes_list_count(target, sizeof(Int));
        if (count <= 0) return;
        Int idx = count - 1;
        Int iv = 0;
        size_t offset = (size_t)idx * sizeof(Int);
        if (!bytes_list_remove(vm, target, offset, &iv, sizeof(Int))) return;
        push_number(vm, stack, (double)iv);
        return;
    }
    if (type == DISTURB_T_FLOAT) {
        Int count = bytes_list_count(target, sizeof(Float));
        if (count <= 0) return;
        Int idx = count - 1;
        Float fv = 0;
        size_t offset = (size_t)idx * sizeof(Float);
        if (!bytes_list_remove(vm, target, offset, &fv, sizeof(Float))) return;
        push_number(vm, stack, (double)fv);
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
    Int type = disturb_obj_type(target->obj);
    if (type == DISTURB_T_TABLE) {
        if (target->obj->size <= 2) return;
        Value v = urb_remove(target->obj, 2);
        ObjEntry *entry = (ObjEntry*)v.p;
        if (entry) {
            stack = push_entry(vm, stack, entry);
        }
        return;
    }
    if (type == DISTURB_T_INT && entry_is_string(target)) {
        size_t len = disturb_bytes_len(target->obj);
        if (!len) return;
        char c = disturb_bytes_data(target->obj)[0];
        memmove(disturb_bytes_data(target->obj), disturb_bytes_data(target->obj) + 1, len - 1);
        target->obj->size = (UHalf)(len - 1 + 2);
        target->obj->capacity = target->obj->size;
        push_string(vm, stack, &c, 1);
        return;
    }
    if (type == DISTURB_T_INT) {
        Int count = bytes_list_count(target, sizeof(Int));
        if (count <= 0) return;
        Int iv = 0;
        if (!bytes_list_remove(vm, target, 0, &iv, sizeof(Int))) return;
        push_number(vm, stack, (double)iv);
        return;
    }
    if (type == DISTURB_T_FLOAT) {
        Int count = bytes_list_count(target, sizeof(Float));
        if (count <= 0) return;
        Float fv = 0;
        if (!bytes_list_remove(vm, target, 0, &fv, sizeof(Float))) return;
        push_number(vm, stack, (double)fv);
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
    Int type = disturb_obj_type(target->obj);
    for (uint32_t i = argc; i-- > start;) {
        ObjEntry *arg = native_arg(stack, argc, i);
        if (!arg) continue;
        if (type == DISTURB_T_TABLE) {
            Value v;
            v.p = arg;
            urb_insert(target->obj, 2, v);
        } else if (type == DISTURB_T_INT && entry_is_string(target)) {
            if (!entry_is_string(arg)) {
                fprintf(stderr, "unshift expects string values\n");
                return;
            }
            size_t len = disturb_bytes_len(target->obj);
            size_t add = disturb_bytes_len(arg->obj);
            size_t bytes = 2 * sizeof(Value) + len + add;
            Value *data = (Value*)realloc(target->obj->data, bytes);
            if (!data && bytes > 0) {
                fprintf(stderr, "unshift failed to grow list\n");
                return;
            }
            if (data) target->obj->data = data;
            memmove(disturb_bytes_data(target->obj) + add, disturb_bytes_data(target->obj), len);
            memcpy(disturb_bytes_data(target->obj), disturb_bytes_data(arg->obj), add);
            target->obj->size = (UHalf)(len + add + 2);
            target->obj->capacity = target->obj->size;
        } else if (type == DISTURB_T_INT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number_scalar(arg, &iv, &fv, &is_float)) {
                fprintf(stderr, "unshift expects number values\n");
                return;
            }
            if (is_float) {
                Int cast = (Int)fv;
                if ((Float)cast != fv) {
                    fprintf(stderr, "unshift expects int values\n");
                    return;
                }
                iv = cast;
            }
            if (!bytes_list_insert(vm, target, 0, &iv, sizeof(Int))) {
                fprintf(stderr, "unshift failed to grow list\n");
                return;
            }
        } else if (type == DISTURB_T_FLOAT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number_scalar(arg, &iv, &fv, &is_float)) {
                fprintf(stderr, "unshift expects number values\n");
                return;
            }
            Float out = is_float ? fv : (Float)iv;
            if (!bytes_list_insert(vm, target, 0, &out, sizeof(Float))) {
                fprintf(stderr, "unshift failed to grow list\n");
                return;
            }
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
    Int type = disturb_obj_type(target->obj);
    if (type == DISTURB_T_TABLE) {
        Value v;
        v.p = val;
        urb_insert(target->obj, list_pos_from_index(target->obj, index), v);
        return;
    }
    if (type == DISTURB_T_INT && entry_is_string(target)) {
        if (!entry_is_string(val)) {
            fprintf(stderr, "insert expects string value\n");
            return;
        }
        size_t len = disturb_bytes_len(target->obj);
        size_t add = disturb_bytes_len(val->obj);
        Int insert_at = bytes_list_insert_index((Int)len, index);
        if (!bytes_list_insert(vm, target, (size_t)insert_at, disturb_bytes_data(val->obj), add)) {
            fprintf(stderr, "insert failed to grow string\n");
            return;
        }
        return;
    }
    if (type == DISTURB_T_INT) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(val, &iv, &fv, &is_float)) {
            fprintf(stderr, "insert expects number value\n");
            return;
        }
        if (is_float) {
            Int cast = (Int)fv;
            if ((Float)cast != fv) {
                fprintf(stderr, "insert expects int value\n");
                return;
            }
            iv = cast;
        }
        Int count = bytes_list_count(target, sizeof(Int));
        Int insert_at = bytes_list_insert_index(count, index);
        size_t offset = (size_t)insert_at * sizeof(Int);
        if (!bytes_list_insert(vm, target, offset, &iv, sizeof(Int))) {
            fprintf(stderr, "insert failed to grow list\n");
            return;
        }
        return;
    }
    if (type == DISTURB_T_FLOAT) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(val, &iv, &fv, &is_float)) {
            fprintf(stderr, "insert expects number value\n");
            return;
        }
        Float out = is_float ? fv : (Float)iv;
        Int count = bytes_list_count(target, sizeof(Float));
        Int insert_at = bytes_list_insert_index(count, index);
        size_t offset = (size_t)insert_at * sizeof(Float);
        if (!bytes_list_insert(vm, target, offset, &out, sizeof(Float))) {
            fprintf(stderr, "insert failed to grow list\n");
            return;
        }
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
    Int type = disturb_obj_type(target->obj);
    if (type == DISTURB_T_TABLE) {
        if (entry_is_string(idx)) {
            size_t key_len = disturb_bytes_len(idx->obj);
            for (Int i = 2; i < target->obj->size; i++) {
                ObjEntry *entry = (ObjEntry*)target->obj->data[i].p;
                ObjEntry *key = vm_entry_key(entry);
                if (!key || !entry_is_string(key)) continue;
                if (disturb_bytes_len(key->obj) != key_len ||
                    memcmp(disturb_bytes_data(key->obj), disturb_bytes_data(idx->obj), key_len) != 0) {
                    continue;
                }
                Value v = urb_remove(target->obj, i);
                entry = (ObjEntry*)v.p;
                if (entry) {
                    stack = push_entry(vm, stack, entry);
                }
                return;
            }
            return;
        }
        Int index = 0;
        if (!number_to_int(idx, &index)) {
            fprintf(stderr, "remove expects string key or integer index\n");
            return;
        }
        if (target->obj->size <= 2) return;
        Value v = urb_remove(target->obj, list_pos_from_index(target->obj, index));
        ObjEntry *entry = (ObjEntry*)v.p;
        if (entry) {
            stack = push_entry(vm, stack, entry);
        }
        return;
    }
    Int index = 0;
    if (!number_to_int(idx, &index)) {
        fprintf(stderr, "remove expects integer index\n");
        return;
    }
    if (type == DISTURB_T_INT && entry_is_string(target)) {
        size_t len = disturb_bytes_len(target->obj);
        Int pos = 0;
        if (!bytes_list_index((Int)len, index, &pos)) return;
        char c = 0;
        if (!bytes_list_remove(vm, target, (size_t)pos, &c, 1)) return;
        push_string(vm, stack, &c, 1);
        return;
    }
    if (type == DISTURB_T_INT) {
        Int count = bytes_list_count(target, sizeof(Int));
        Int pos = 0;
        if (!bytes_list_index(count, index, &pos)) return;
        Int iv = 0;
        if (!bytes_list_remove(vm, target, (size_t)pos * sizeof(Int), &iv, sizeof(Int))) return;
        push_number(vm, stack, (double)iv);
        return;
    }
    if (type == DISTURB_T_FLOAT) {
        Int count = bytes_list_count(target, sizeof(Float));
        Int pos = 0;
        if (!bytes_list_index(count, index, &pos)) return;
        Float fv = 0;
        if (!bytes_list_remove(vm, target, (size_t)pos * sizeof(Float), &fv, sizeof(Float))) return;
        push_number(vm, stack, (double)fv);
        return;
    }
}

NativeFn vm_lookup_native(const char *name)
{
    if (strcmp(name, "print") == 0) return native_print;
    if (strcmp(name, "println") == 0) return native_println;
    if (strcmp(name, "len") == 0) return native_len;
    if (strcmp(name, "pretty") == 0) return native_pretty;
    if (strcmp(name, "clone") == 0) return native_clone;
    if (strcmp(name, "copy") == 0) return native_copy;
    if (strcmp(name, "toInt") == 0) return native_to_int;
    if (strcmp(name, "toFloat") == 0) return native_to_float;
    #ifdef DISTURB_ENABLE_IO
    if (strcmp(name, "read") == 0) return native_read;
    if (strcmp(name, "write") == 0) return native_write;
    #endif
    #ifndef DISTURB_EMBEDDED
    if (strcmp(name, "import") == 0) return native_import;
    #endif
    #ifdef DISTURB_ENABLE_FFI
    if (strcmp(name, "ffiOpen") == 0) return native_ffi_open;
#endif
    if (strcmp(name, "eval") == 0) return native_eval;
    if (strcmp(name, "parse") == 0) return native_parse;
    if (strcmp(name, "emit") == 0) return native_emit;
    if (strcmp(name, "bytecodeToAst") == 0) return native_bytecode_to_ast;
    if (strcmp(name, "astToSource") == 0) return native_ast_to_source;
    if (strcmp(name, "evalBytecode") == 0) return native_eval_bytecode;
    if (strcmp(name, "gcCollect") == 0) return native_gc_collect;
    if (strcmp(name, "gcFree") == 0) return native_gc_free;
    if (strcmp(name, "gcSweep") == 0) return native_gc_sweep;
    if (strcmp(name, "gcNew") == 0) return native_gc_new;
    if (strcmp(name, "gcFlush") == 0) return native_gc_flush;
    if (strcmp(name, "gcDebug") == 0) return native_gc_debug;
    if (strcmp(name, "gcStats") == 0) return native_gc_stats;
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
    if (strcmp(name, "find") == 0) return native_find;
    if (strcmp(name, "rfind") == 0) return native_rfind;
    if (strcmp(name, "contains") == 0) return native_contains;
    if (strcmp(name, "replace") == 0) return native_replace;
    if (strcmp(name, "replaceAll") == 0) return native_replace_all;
    if (strcmp(name, "papagaio") == 0) return native_papagaio;
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
    return NULL;
}
