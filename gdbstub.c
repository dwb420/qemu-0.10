/*
 * gdb server stub
 *
 * Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA  02110-1301 USA
 */
#include "config.h"
#include "qemu-common.h"
#include "qemu-char.h"
#include "sysemu.h"
#include "gdbstub.h"

#define MAX_PACKET_LENGTH 4096

#include "qemu_socket.h"


enum {
    GDB_SIGNAL_0 = 0,
    GDB_SIGNAL_INT = 2,
    GDB_SIGNAL_TRAP = 5,
    GDB_SIGNAL_UNKNOWN = 143
};

/* In system mode we only need SIGINT and SIGTRAP; other signals
   are not yet supported.  */

enum {
    TARGET_SIGINT = 2,
    TARGET_SIGTRAP = 5
};

static int gdb_signal_table[] = {
    -1,
    -1,
    TARGET_SIGINT,
    -1,
    -1,
    TARGET_SIGTRAP
};

static int gdb_signal_to_target (int sig)
{
    if (sig < ARRAY_SIZE (gdb_signal_table))
        return gdb_signal_table[sig];
    else
        return -1;
}

//#define DEBUG_GDB

typedef struct GDBRegisterState {
    int base_reg;
    int num_regs;
    gdb_reg_cb get_reg;
    gdb_reg_cb set_reg;
    const char *xml;
    struct GDBRegisterState *next;
} GDBRegisterState;

enum RSState {
    RS_IDLE,
    RS_GETLINE,
    RS_CHKSUM1,
    RS_CHKSUM2,
    RS_SYSCALL,
};
typedef struct GDBState {
    CPUState *c_cpu; /* current CPU for step/continue ops */
    CPUState *g_cpu; /* current CPU for other ops */
    CPUState *query_cpu; /* for q{f|s}ThreadInfo */
    enum RSState state; /* parsing state */
    char line_buf[MAX_PACKET_LENGTH];
    int line_buf_index;
    int line_csum;
    uint8_t last_packet[MAX_PACKET_LENGTH + 4];
    int last_packet_len;
    int signal;
    CharDriverState *chr;
} GDBState;

/* By default use no IRQs and no timers while single stepping so as to
 * make single stepping like an ICE HW step.
 */
static int sstep_flags = SSTEP_ENABLE|SSTEP_NOIRQ|SSTEP_NOTIMER;

static GDBState *gdbserver_state;

/* This is an ugly hack to cope with both new and old gdb.
   If gdb sends qXfer:features:read then assume we're talking to a newish
   gdb that understands target descriptions.  */
static int gdb_has_xml;

static gdb_syscall_complete_cb gdb_current_syscall_cb;

enum {
    GDB_SYS_UNKNOWN,
    GDB_SYS_ENABLED,
    GDB_SYS_DISABLED,
} gdb_syscall_mode;

/* If gdb is connected when the first semihosting syscall occurs then use
   remote gdb syscalls.  Otherwise use native file IO.  */
int use_gdb_syscalls(void)
{
    if (gdb_syscall_mode == GDB_SYS_UNKNOWN) {
        gdb_syscall_mode = (gdbserver_state ? GDB_SYS_ENABLED
                                            : GDB_SYS_DISABLED);
    }
    return gdb_syscall_mode == GDB_SYS_ENABLED;
}

/* Resume execution.  */
static inline void gdb_continue(GDBState *s)
{
    vm_start();
}

static void put_buffer(GDBState *s, const uint8_t *buf, int len)
{
    qemu_chr_write(s->chr, buf, len);
}

static inline int fromhex(int v)
{
    if (v >= '0' && v <= '9')
        return v - '0';
    else if (v >= 'A' && v <= 'F')
        return v - 'A' + 10;
    else if (v >= 'a' && v <= 'f')
        return v - 'a' + 10;
    else
        return 0;
}

static inline int tohex(int v)
{
    if (v < 10)
        return v + '0';
    else
        return v - 10 + 'a';
}

static void memtohex(char *buf, const uint8_t *mem, int len)
{
    int i, c;
    char *q;
    q = buf;
    for(i = 0; i < len; i++) {
        c = mem[i];
        *q++ = tohex(c >> 4);
        *q++ = tohex(c & 0xf);
    }
    *q = '\0';
}

static void hextomem(uint8_t *mem, const char *buf, int len)
{
    int i;

    for(i = 0; i < len; i++) {
        mem[i] = (fromhex(buf[0]) << 4) | fromhex(buf[1]);
        buf += 2;
    }
}

/* return -1 if error, 0 if OK */
static int put_packet_binary(GDBState *s, const char *buf, int len)
{
    int csum, i;
    uint8_t *p;

    for(;;) {
        p = s->last_packet;
        *(p++) = '$';
        memcpy(p, buf, len);
        p += len;
        csum = 0;
        for(i = 0; i < len; i++) {
            csum += buf[i];
        }
        *(p++) = '#';
        *(p++) = tohex((csum >> 4) & 0xf);
        *(p++) = tohex((csum) & 0xf);

        s->last_packet_len = p - s->last_packet;
        put_buffer(s, (uint8_t *)s->last_packet, s->last_packet_len);
        break;
    }
    return 0;
}

/* return -1 if error, 0 if OK */
static int put_packet(GDBState *s, const char *buf)
{
#ifdef DEBUG_GDB
    printf("reply='%s'\n", buf);
#endif

    return put_packet_binary(s, buf, strlen(buf));
}

/* The GDB remote protocol transfers values in target byte order.  This means
   we can use the raw memory access routines to access the value buffer.
   Conveniently, these also handle the case where the buffer is mis-aligned.
 */
#define GET_REG8(val) do { \
    stb_p(mem_buf, val); \
    return 1; \
    } while(0)
#define GET_REG16(val) do { \
    stw_p(mem_buf, val); \
    return 2; \
    } while(0)
#define GET_REG32(val) do { \
    stl_p(mem_buf, val); \
    return 4; \
    } while(0)
#define GET_REG64(val) do { \
    stq_p(mem_buf, val); \
    return 8; \
    } while(0)

#if TARGET_LONG_BITS == 64
#define GET_REGL(val) GET_REG64(val)
#define ldtul_p(addr) ldq_p(addr)
#else
#define GET_REGL(val) GET_REG32(val)
#define ldtul_p(addr) ldl_p(addr)
#endif


#ifdef TARGET_X86_64
static const int gpr_map[16] = {
    R_EAX, R_EBX, R_ECX, R_EDX, R_ESI, R_EDI, R_EBP, R_ESP,
    8, 9, 10, 11, 12, 13, 14, 15
};
#else
static const int gpr_map[8] = {0, 1, 2, 3, 4, 5, 6, 7};
#endif

#define NUM_CORE_REGS (CPU_NB_REGS * 2 + 25)

static int cpu_gdb_read_register(CPUState *env, uint8_t *mem_buf, int n)
{
    if (n < CPU_NB_REGS) {
        GET_REGL(env->regs[gpr_map[n]]);
    } else if (n >= CPU_NB_REGS + 8 && n < CPU_NB_REGS + 16) {
        /* FIXME: byteswap float values.  */
#ifdef USE_X86LDOUBLE
        memcpy(mem_buf, &env->fpregs[n - (CPU_NB_REGS + 8)], 10);
#else
        memset(mem_buf, 0, 10);
#endif
        return 10;
    } else if (n >= CPU_NB_REGS + 24) {
        n -= CPU_NB_REGS + 24;
        if (n < CPU_NB_REGS) {
            stq_p(mem_buf, env->xmm_regs[n].XMM_Q(0));
            stq_p(mem_buf + 8, env->xmm_regs[n].XMM_Q(1));
            return 16;
        } else if (n == CPU_NB_REGS) {
            GET_REG32(env->mxcsr);
        }
    } else {
        n -= CPU_NB_REGS;
        switch (n) {
        case 0: GET_REGL(env->eip);
        case 1: GET_REG32(env->eflags);
        case 2: GET_REG32(env->segs[R_CS].selector);
        case 3: GET_REG32(env->segs[R_SS].selector);
        case 4: GET_REG32(env->segs[R_DS].selector);
        case 5: GET_REG32(env->segs[R_ES].selector);
        case 6: GET_REG32(env->segs[R_FS].selector);
        case 7: GET_REG32(env->segs[R_GS].selector);
        /* 8...15 x87 regs.  */
        case 16: GET_REG32(env->fpuc);
        case 17: GET_REG32((env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11);
        case 18: GET_REG32(0); /* ftag */
        case 19: GET_REG32(0); /* fiseg */
        case 20: GET_REG32(0); /* fioff */
        case 21: GET_REG32(0); /* foseg */
        case 22: GET_REG32(0); /* fooff */
        case 23: GET_REG32(0); /* fop */
        /* 24+ xmm regs.  */
        }
    }
    return 0;
}

static int cpu_gdb_write_register(CPUState *env, uint8_t *mem_buf, int i)
{
    uint32_t tmp;

    if (i < CPU_NB_REGS) {
        env->regs[gpr_map[i]] = ldtul_p(mem_buf);
        return sizeof(target_ulong);
    } else if (i >= CPU_NB_REGS + 8 && i < CPU_NB_REGS + 16) {
        i -= CPU_NB_REGS + 8;
#ifdef USE_X86LDOUBLE
        memcpy(&env->fpregs[i], mem_buf, 10);
#endif
        return 10;
    } else if (i >= CPU_NB_REGS + 24) {
        i -= CPU_NB_REGS + 24;
        if (i < CPU_NB_REGS) {
            env->xmm_regs[i].XMM_Q(0) = ldq_p(mem_buf);
            env->xmm_regs[i].XMM_Q(1) = ldq_p(mem_buf + 8);
            return 16;
        } else if (i == CPU_NB_REGS) {
            env->mxcsr = ldl_p(mem_buf);
            return 4;
        }
    } else {
        i -= CPU_NB_REGS;
        switch (i) {
        case 0: env->eip = ldtul_p(mem_buf); return sizeof(target_ulong);
        case 1: env->eflags = ldl_p(mem_buf); return 4;
/* FIXME: Honor segment registers.  Needs to avoid raising an exception
   when the selector is invalid.  */
#define LOAD_SEG(index, sreg) do {} while(0)
        case 2: LOAD_SEG(10, R_CS); return 4;
        case 3: LOAD_SEG(11, R_SS); return 4;
        case 4: LOAD_SEG(12, R_DS); return 4;
        case 5: LOAD_SEG(13, R_ES); return 4;
        case 6: LOAD_SEG(14, R_FS); return 4;
        case 7: LOAD_SEG(15, R_GS); return 4;
        /* 8...15 x87 regs.  */
        case 16: env->fpuc = ldl_p(mem_buf); return 4;
        case 17:
                 tmp = ldl_p(mem_buf);
                 env->fpstt = (tmp >> 11) & 7;
                 env->fpus = tmp & ~0x3800;
                 return 4;
        case 18: /* ftag */ return 4;
        case 19: /* fiseg */ return 4;
        case 20: /* fioff */ return 4;
        case 21: /* foseg */ return 4;
        case 22: /* fooff */ return 4;
        case 23: /* fop */ return 4;
        /* 24+ xmm regs.  */
        }
    }
    /* Unrecognised register.  */
    return 0;
}

static int num_g_regs = NUM_CORE_REGS;

#ifdef GDB_CORE_XML
/* Encode data using the encoding for 'x' packets.  */
static int memtox(char *buf, const char *mem, int len)
{
    char *p = buf;
    char c;

    while (len--) {
        c = *(mem++);
        switch (c) {
        case '#': case '$': case '*': case '}':
            *(p++) = '}';
            *(p++) = c ^ 0x20;
            break;
        default:
            *(p++) = c;
            break;
        }
    }
    return p - buf;
}

static const char *get_feature_xml(const char *p, const char **newp)
{
    extern const char *const xml_builtin[][2];
    size_t len;
    int i;
    const char *name;
    static char target_xml[1024];

    len = 0;
    while (p[len] && p[len] != ':')
        len++;
    *newp = p + len;

    name = NULL;
    if (strncmp(p, "target.xml", len) == 0) {
        /* Generate the XML description for this CPU.  */
        if (!target_xml[0]) {
            GDBRegisterState *r;

            snprintf(target_xml, sizeof(target_xml),
                     "<?xml version=\"1.0\"?>"
                     "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
                     "<target>"
                     "<xi:include href=\"%s\"/>",
                     GDB_CORE_XML);

            for (r = first_cpu->gdb_regs; r; r = r->next) {
                strcat(target_xml, "<xi:include href=\"");
                strcat(target_xml, r->xml);
                strcat(target_xml, "\"/>");
            }
            strcat(target_xml, "</target>");
        }
        return target_xml;
    }
    for (i = 0; ; i++) {
        name = xml_builtin[i][0];
        if (!name || (strncmp(name, p, len) == 0 && strlen(name) == len))
            break;
    }
    return name ? xml_builtin[i][1] : NULL;
}
#endif

static int gdb_read_register(CPUState *env, uint8_t *mem_buf, int reg)
{
    GDBRegisterState *r;

    if (reg < NUM_CORE_REGS)
        return cpu_gdb_read_register(env, mem_buf, reg);

    for (r = env->gdb_regs; r; r = r->next) {
        if (r->base_reg <= reg && reg < r->base_reg + r->num_regs) {
            return r->get_reg(env, mem_buf, reg - r->base_reg);
        }
    }
    return 0;
}

static int gdb_write_register(CPUState *env, uint8_t *mem_buf, int reg)
{
    GDBRegisterState *r;

    if (reg < NUM_CORE_REGS)
        return cpu_gdb_write_register(env, mem_buf, reg);

    for (r = env->gdb_regs; r; r = r->next) {
        if (r->base_reg <= reg && reg < r->base_reg + r->num_regs) {
            return r->set_reg(env, mem_buf, reg - r->base_reg);
        }
    }
    return 0;
}

/* Register a supplemental set of CPU registers.  If g_pos is nonzero it
   specifies the first register number and these registers are included in
   a standard "g" packet.  Direction is relative to gdb, i.e. get_reg is
   gdb reading a CPU register, and set_reg is gdb modifying a CPU register.
 */

void gdb_register_coprocessor(CPUState * env,
                             gdb_reg_cb get_reg, gdb_reg_cb set_reg,
                             int num_regs, const char *xml, int g_pos)
{
    GDBRegisterState *s;
    GDBRegisterState **p;
    static int last_reg = NUM_CORE_REGS;

    s = (GDBRegisterState *)qemu_mallocz(sizeof(GDBRegisterState));
    s->base_reg = last_reg;
    s->num_regs = num_regs;
    s->get_reg = get_reg;
    s->set_reg = set_reg;
    s->xml = xml;
    p = &env->gdb_regs;
    while (*p) {
        /* Check for duplicates.  */
        if (strcmp((*p)->xml, xml) == 0)
            return;
        p = &(*p)->next;
    }
    /* Add to end of list.  */
    last_reg += num_regs;
    *p = s;
    if (g_pos) {
        if (g_pos != s->base_reg) {
            fprintf(stderr, "Error: Bad gdb register numbering for '%s'\n"
                    "Expected %d got %d\n", xml, g_pos, s->base_reg);
        } else {
            num_g_regs = last_reg;
        }
    }
}

/* GDB breakpoint/watchpoint types */
#define GDB_BREAKPOINT_SW        0
#define GDB_BREAKPOINT_HW        1
#define GDB_WATCHPOINT_WRITE     2
#define GDB_WATCHPOINT_READ      3
#define GDB_WATCHPOINT_ACCESS    4

static const int xlat_gdb_type[] = {
    [GDB_WATCHPOINT_WRITE]  = BP_GDB | BP_MEM_WRITE,
    [GDB_WATCHPOINT_READ]   = BP_GDB | BP_MEM_READ,
    [GDB_WATCHPOINT_ACCESS] = BP_GDB | BP_MEM_ACCESS,
};

static int gdb_breakpoint_insert(target_ulong addr, target_ulong len, int type)
{
    CPUState *env;
    int err = 0;

    switch (type) {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
        for (env = first_cpu; env != NULL; env = env->next_cpu) {
            err = cpu_breakpoint_insert(env, addr, BP_GDB, NULL);
            if (err)
                break;
        }
        return err;
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
        for (env = first_cpu; env != NULL; env = env->next_cpu) {
            err = cpu_watchpoint_insert(env, addr, len, xlat_gdb_type[type],
                                        NULL);
            if (err)
                break;
        }
        return err;
    default:
        return -ENOSYS;
    }
}

static int gdb_breakpoint_remove(target_ulong addr, target_ulong len, int type)
{
    CPUState *env;
    int err = 0;

    switch (type) {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
        for (env = first_cpu; env != NULL; env = env->next_cpu) {
            err = cpu_breakpoint_remove(env, addr, BP_GDB);
            if (err)
                break;
        }
        return err;
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
        for (env = first_cpu; env != NULL; env = env->next_cpu) {
            err = cpu_watchpoint_remove(env, addr, len, xlat_gdb_type[type]);
            if (err)
                break;
        }
        return err;
    default:
        return -ENOSYS;
    }
}

static void gdb_breakpoint_remove_all(void)
{
    CPUState *env;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        cpu_breakpoint_remove_all(env, BP_GDB);
        cpu_watchpoint_remove_all(env, BP_GDB);
    }
}

static int gdb_handle_packet(GDBState *s, const char *line_buf)
{
    CPUState *env;
    const char *p;
    int ch, reg_size, type, res, thread;
    char buf[MAX_PACKET_LENGTH];
    uint8_t mem_buf[MAX_PACKET_LENGTH];
    uint8_t *registers;
    target_ulong addr, len;

#ifdef DEBUG_GDB
    printf("command='%s'\n", line_buf);
#endif
    p = line_buf;
    ch = *p++;
    switch(ch) {
    case '?':
        /* TODO: Make this return the correct value for user-mode.  */
        snprintf(buf, sizeof(buf), "T%02xthread:%02x;", GDB_SIGNAL_TRAP,
                 s->c_cpu->cpu_index+1);
        put_packet(s, buf);
        /* Remove all the breakpoints when this query is issued,
         * because gdb is doing and initial connect and the state
         * should be cleaned up.
         */
        gdb_breakpoint_remove_all();
        break;
    case 'c':
        if (*p != '\0') {
            addr = strtoull(p, (char **)&p, 16);
            s->c_cpu->eip = addr;
        }
        s->signal = 0;
        gdb_continue(s);
    return RS_IDLE;
    case 'C':
        s->signal = gdb_signal_to_target (strtoul(p, (char **)&p, 16));
        if (s->signal == -1)
            s->signal = 0;
        gdb_continue(s);
        return RS_IDLE;
    case 'k':
        /* Kill the target */
        fprintf(stderr, "\nQEMU: Terminated via GDBstub\n");
        exit(0);
    case 'D':
        /* Detach packet */
        gdb_breakpoint_remove_all();
        gdb_continue(s);
        put_packet(s, "OK");
        break;
    case 's':
        if (*p != '\0') {
            addr = strtoull(p, (char **)&p, 16);
            s->c_cpu->eip = addr;
        }
        cpu_single_step(s->c_cpu, sstep_flags);
        gdb_continue(s);
    return RS_IDLE;
    case 'F':
        {
            target_ulong ret;
            target_ulong err;

            ret = strtoull(p, (char **)&p, 16);
            if (*p == ',') {
                p++;
                err = strtoull(p, (char **)&p, 16);
            } else {
                err = 0;
            }
            if (*p == ',')
                p++;
            type = *p;
            if (gdb_current_syscall_cb)
                gdb_current_syscall_cb(s->c_cpu, ret, err);
            if (type == 'C') {
                put_packet(s, "T02");
            } else {
                gdb_continue(s);
            }
        }
        break;
    case 'g':
        len = 0;
        for (addr = 0; addr < num_g_regs; addr++) {
            reg_size = gdb_read_register(s->g_cpu, mem_buf + len, addr);
            len += reg_size;
        }
        memtohex(buf, mem_buf, len);
        put_packet(s, buf);
        break;
    case 'G':
        registers = mem_buf;
        len = strlen(p) / 2;
        hextomem((uint8_t *)registers, p, len);
        for (addr = 0; addr < num_g_regs && len > 0; addr++) {
            reg_size = gdb_write_register(s->g_cpu, registers, addr);
            len -= reg_size;
            registers += reg_size;
        }
        put_packet(s, "OK");
        break;
    case 'm':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, NULL, 16);
        if (cpu_memory_rw_debug(s->g_cpu, addr, mem_buf, len, 0) != 0) {
            put_packet (s, "E14");
        } else {
            memtohex(buf, mem_buf, len);
            put_packet(s, buf);
        }
        break;
    case 'M':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, (char **)&p, 16);
        if (*p == ':')
            p++;
        hextomem(mem_buf, p, len);
        if (cpu_memory_rw_debug(s->g_cpu, addr, mem_buf, len, 1) != 0)
            put_packet(s, "E14");
        else
            put_packet(s, "OK");
        break;
    case 'p':
        /* Older gdb are really dumb, and don't use 'g' if 'p' is avaialable.
           This works, but can be very slow.  Anything new enough to
           understand XML also knows how to use this properly.  */
        if (!gdb_has_xml)
            goto unknown_command;
        addr = strtoull(p, (char **)&p, 16);
        reg_size = gdb_read_register(s->g_cpu, mem_buf, addr);
        if (reg_size) {
            memtohex(buf, mem_buf, reg_size);
            put_packet(s, buf);
        } else {
            put_packet(s, "E14");
        }
        break;
    case 'P':
        if (!gdb_has_xml)
            goto unknown_command;
        addr = strtoull(p, (char **)&p, 16);
        if (*p == '=')
            p++;
        reg_size = strlen(p) / 2;
        hextomem(mem_buf, p, reg_size);
        gdb_write_register(s->g_cpu, mem_buf, addr);
        put_packet(s, "OK");
        break;
    case 'Z':
    case 'z':
        type = strtoul(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, (char **)&p, 16);
        if (ch == 'Z')
            res = gdb_breakpoint_insert(addr, len, type);
        else
            res = gdb_breakpoint_remove(addr, len, type);
        if (res >= 0)
             put_packet(s, "OK");
        else if (res == -ENOSYS)
            put_packet(s, "");
        else
            put_packet(s, "E22");
        break;
    case 'H':
        type = *p++;
        thread = strtoull(p, (char **)&p, 16);
        if (thread == -1 || thread == 0) {
            put_packet(s, "OK");
            break;
        }
        for (env = first_cpu; env != NULL; env = env->next_cpu)
            if (env->cpu_index + 1 == thread)
                break;
        if (env == NULL) {
            put_packet(s, "E22");
            break;
        }
        switch (type) {
        case 'c':
            s->c_cpu = env;
            put_packet(s, "OK");
            break;
        case 'g':
            s->g_cpu = env;
            put_packet(s, "OK");
            break;
        default:
             put_packet(s, "E22");
             break;
        }
        break;
    case 'T':
        thread = strtoull(p, (char **)&p, 16);
        if (thread > 0 && thread < smp_cpus + 1)
             put_packet(s, "OK");
        else
            put_packet(s, "E22");
        break;
    case 'q':
    case 'Q':
        /* parse any 'q' packets here */
        if (!strcmp(p,"qemu.sstepbits")) {
            /* Query Breakpoint bit definitions */
            snprintf(buf, sizeof(buf), "ENABLE=%x,NOIRQ=%x,NOTIMER=%x",
                     SSTEP_ENABLE,
                     SSTEP_NOIRQ,
                     SSTEP_NOTIMER);
            put_packet(s, buf);
            break;
        } else if (strncmp(p,"qemu.sstep",10) == 0) {
            /* Display or change the sstep_flags */
            p += 10;
            if (*p != '=') {
                /* Display current setting */
                snprintf(buf, sizeof(buf), "0x%x", sstep_flags);
                put_packet(s, buf);
                break;
            }
            p++;
            type = strtoul(p, (char **)&p, 16);
            sstep_flags = type;
            put_packet(s, "OK");
            break;
        } else if (strcmp(p,"C") == 0) {
            /* "Current thread" remains vague in the spec, so always return
             *  the first CPU (gdb returns the first thread). */
            put_packet(s, "QC1");
            break;
        } else if (strcmp(p,"fThreadInfo") == 0) {
            s->query_cpu = first_cpu;
            goto report_cpuinfo;
        } else if (strcmp(p,"sThreadInfo") == 0) {
        report_cpuinfo:
            if (s->query_cpu) {
                snprintf(buf, sizeof(buf), "m%x", s->query_cpu->cpu_index+1);
                put_packet(s, buf);
                s->query_cpu = s->query_cpu->next_cpu;
            } else
                put_packet(s, "l");
            break;
        } else if (strncmp(p,"ThreadExtraInfo,", 16) == 0) {
            thread = strtoull(p+16, (char **)&p, 16);
            for (env = first_cpu; env != NULL; env = env->next_cpu)
                if (env->cpu_index + 1 == thread) {
                    len = snprintf((char *)mem_buf, sizeof(mem_buf),
                                   "CPU#%d [%s]", env->cpu_index,
                                   env->halted ? "halted " : "running");
                    memtohex(buf, mem_buf, len);
                    put_packet(s, buf);
                    break;
                }
            break;
        }
        if (strncmp(p, "Supported", 9) == 0) {
            snprintf(buf, sizeof(buf), "PacketSize=%x", MAX_PACKET_LENGTH);
#ifdef GDB_CORE_XML
            strcat(buf, ";qXfer:features:read+");
#endif
            put_packet(s, buf);
            break;
        }
#ifdef GDB_CORE_XML
        if (strncmp(p, "Xfer:features:read:", 19) == 0) {
            const char *xml;
            target_ulong total_len;

            gdb_has_xml = 1;
            p += 19;
            xml = get_feature_xml(p, &p);
            if (!xml) {
                snprintf(buf, sizeof(buf), "E00");
                put_packet(s, buf);
                break;
            }

            if (*p == ':')
                p++;
            addr = strtoul(p, (char **)&p, 16);
            if (*p == ',')
                p++;
            len = strtoul(p, (char **)&p, 16);

            total_len = strlen(xml);
            if (addr > total_len) {
                snprintf(buf, sizeof(buf), "E00");
                put_packet(s, buf);
                break;
            }
            if (len > (MAX_PACKET_LENGTH - 5) / 2)
                len = (MAX_PACKET_LENGTH - 5) / 2;
            if (len < total_len - addr) {
                buf[0] = 'm';
                len = memtox(buf + 1, xml + addr, len);
            } else {
                buf[0] = 'l';
                len = memtox(buf + 1, xml + addr, total_len - addr);
            }
            put_packet_binary(s, buf, len + 1);
            break;
        }
#endif
        /* Unrecognised 'q' command.  */
        goto unknown_command;

    default:
    unknown_command:
        /* put empty packet */
        buf[0] = '\0';
        put_packet(s, buf);
        break;
    }
    return RS_IDLE;
}

void gdb_set_stop_cpu(CPUState *env)
{
    gdbserver_state->c_cpu = env;
    gdbserver_state->g_cpu = env;
}

static void gdb_vm_state_change(void *opaque, int running, int reason)
{
    GDBState *s = gdbserver_state;
    CPUState *env = s->c_cpu;
    char buf[256];
    const char *type;
    int ret;

    if (running || (reason != EXCP_DEBUG && reason != EXCP_INTERRUPT) ||
        s->state == RS_SYSCALL)
        return;

    /* disable single step if it was enable */
    cpu_single_step(env, 0);

    if (reason == EXCP_DEBUG) {
        if (env->watchpoint_hit) {
            switch (env->watchpoint_hit->flags & BP_MEM_ACCESS) {
            case BP_MEM_READ:
                type = "r";
                break;
            case BP_MEM_ACCESS:
                type = "a";
                break;
            default:
                type = "";
                break;
            }
            snprintf(buf, sizeof(buf),
                     "T%02xthread:%02x;%swatch:" TARGET_FMT_lx ";",
                     GDB_SIGNAL_TRAP, env->cpu_index+1, type,
                     env->watchpoint_hit->vaddr);
            put_packet(s, buf);
            env->watchpoint_hit = NULL;
            return;
        }
    tb_flush(env);
        ret = GDB_SIGNAL_TRAP;
    } else {
        ret = GDB_SIGNAL_INT;
    }
    snprintf(buf, sizeof(buf), "T%02xthread:%02x;", ret, env->cpu_index+1);
    put_packet(s, buf);
}

/* Send a gdb syscall request.
   This accepts limited printf-style format specifiers, specifically:
    %x  - target_ulong argument printed in hex.
    %lx - 64-bit argument printed in hex.
    %s  - string pointer (target_ulong) and length (int) pair.  */
void gdb_do_syscall(gdb_syscall_complete_cb cb, const char *fmt, ...)
{
    va_list va;
    char buf[256];
    char *p;
    target_ulong addr;
    uint64_t i64;
    GDBState *s;

    s = gdbserver_state;
    if (!s)
        return;
    gdb_current_syscall_cb = cb;
    s->state = RS_SYSCALL;
    vm_stop(EXCP_DEBUG);
    s->state = RS_IDLE;
    va_start(va, fmt);
    p = buf;
    *(p++) = 'F';
    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            switch (*fmt++) {
            case 'x':
                addr = va_arg(va, target_ulong);
                p += snprintf(p, &buf[sizeof(buf)] - p, TARGET_FMT_lx, addr);
                break;
            case 'l':
                if (*(fmt++) != 'x')
                    goto bad_format;
                i64 = va_arg(va, uint64_t);
                p += snprintf(p, &buf[sizeof(buf)] - p, "%" PRIx64, i64);
                break;
            case 's':
                addr = va_arg(va, target_ulong);
                p += snprintf(p, &buf[sizeof(buf)] - p, TARGET_FMT_lx "/%x",
                              addr, va_arg(va, int));
                break;
            default:
            bad_format:
                fprintf(stderr, "gdbstub: Bad syscall format string '%s'\n",
                        fmt - 1);
                break;
            }
        } else {
            *(p++) = *(fmt++);
        }
    }
    *p = 0;
    va_end(va);
    put_packet(s, buf);
    cpu_interrupt(s->c_cpu, CPU_INTERRUPT_EXIT);
}

static void gdb_read_byte(GDBState *s, int ch)
{
    int i, csum;
    uint8_t reply;

    if (s->last_packet_len) {
        /* Waiting for a response to the last packet.  If we see the start
           of a new command then abandon the previous response.  */
        if (ch == '-') {
#ifdef DEBUG_GDB
            printf("Got NACK, retransmitting\n");
#endif
            put_buffer(s, (uint8_t *)s->last_packet, s->last_packet_len);
        }
#ifdef DEBUG_GDB
        else if (ch == '+')
            printf("Got ACK\n");
        else
            printf("Got '%c' when expecting ACK/NACK\n", ch);
#endif
        if (ch == '+' || ch == '$')
            s->last_packet_len = 0;
        if (ch != '$')
            return;
    }
    if (vm_running) {
        /* when the CPU is running, we cannot do anything except stop
           it when receiving a char */
        vm_stop(EXCP_INTERRUPT);
    } else
    {
        switch(s->state) {
        case RS_IDLE:
            if (ch == '$') {
                s->line_buf_index = 0;
                s->state = RS_GETLINE;
            }
            break;
        case RS_GETLINE:
            if (ch == '#') {
            s->state = RS_CHKSUM1;
            } else if (s->line_buf_index >= sizeof(s->line_buf) - 1) {
                s->state = RS_IDLE;
            } else {
            s->line_buf[s->line_buf_index++] = ch;
            }
            break;
        case RS_CHKSUM1:
            s->line_buf[s->line_buf_index] = '\0';
            s->line_csum = fromhex(ch) << 4;
            s->state = RS_CHKSUM2;
            break;
        case RS_CHKSUM2:
            s->line_csum |= fromhex(ch);
            csum = 0;
            for(i = 0; i < s->line_buf_index; i++) {
                csum += s->line_buf[i];
            }
            if (s->line_csum != (csum & 0xff)) {
                reply = '-';
                put_buffer(s, &reply, 1);
                s->state = RS_IDLE;
            } else {
                reply = '+';
                put_buffer(s, &reply, 1);
                s->state = gdb_handle_packet(s, s->line_buf);
            }
            break;
        default:
            abort();
        }
    }
}

static int gdb_chr_can_receive(void *opaque)
{
  /* We can handle an arbitrarily large amount of data.
   Pick the maximum packet size, which is as good as anything.  */
  return MAX_PACKET_LENGTH;
}

static void gdb_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        gdb_read_byte(gdbserver_state, buf[i]);
    }
}

static void gdb_chr_event(void *opaque, int event)
{
    switch (event) {
    case CHR_EVENT_RESET:
        vm_stop(EXCP_INTERRUPT);
        gdb_has_xml = 0;
        break;
    default:
        break;
    }
}

int gdbserver_start(const char *port)
{
    GDBState *s;
    char gdbstub_port_name[128];
    int port_num;
    char *p;
    CharDriverState *chr;

    if (!port || !*port)
      return -1;

    port_num = strtol(port, &p, 10);
    if (*p == 0) {
        /* A numeric value is interpreted as a port number.  */
        snprintf(gdbstub_port_name, sizeof(gdbstub_port_name),
                 "tcp::%d,nowait,nodelay,server", port_num);
        port = gdbstub_port_name;
    }

    chr = qemu_chr_open("gdb", port, NULL);
    if (!chr)
        return -1;

    s = qemu_mallocz(sizeof(GDBState));
    s->c_cpu = first_cpu;
    s->g_cpu = first_cpu;
    s->chr = chr;
    gdbserver_state = s;
    qemu_chr_add_handlers(chr, gdb_chr_can_receive, gdb_chr_receive,
                          gdb_chr_event, NULL);
    qemu_add_vm_change_state_handler(gdb_vm_state_change, NULL);
    return 0;
}
