#!/usr/bin/env python

import sys
import ctypes
import argparse

from pathlib import Path

from bcc import BPF

# Taken from PAM headers
# ----------------------
# pam_start(const char *service_name, const char *user,
# 	  const struct pam_conv *pam_conversation,
# 	  pam_handle_t **pamh);
#
# extern int
# pam_start_confdir(const char *service_name, const char *user,
# 		  const struct pam_conv *pam_conversation,
# 		  const char *confdir, pam_handle_t **pamh);
#
# extern int
# pam_end(pam_handle_t *pamh, int pam_status);
#
# /* Authentication API's */
#
# extern int
# pam_authenticate(pam_handle_t *pamh, int flags);
#
# extern int
# pam_setcred(pam_handle_t *pamh, int flags);
#
# /* Account Management API's */
#
# extern int
# pam_acct_mgmt(pam_handle_t *pamh, int flags);
#
# /* Session Management API's */
#
# extern int
# pam_open_session(pam_handle_t *pamh, int flags);
#
# extern int
# pam_close_session(pam_handle_t *pamh, int flags);
#
# /* Password Management API's */
#
# extern int
# pam_chauthtok(pam_handle_t *pamh, int flags);

PROGRAM = r'''
#include <linux/sched.h>

#define XSTR(s) STR(s)
#define STR(s) #s

/* Private structure
 * Some pointers made void to reduce complexity
 */
typedef struct pam_handle {
    char *authtok;
    unsigned caller_is;
    void *pam_conversation;
    char *oldauthtok;
    char *prompt;
    char *service_name;
    char *user;
    char *rhost;
    char *ruser;
    char *tty;
    char *xdisplay;
    char *authtok_type;

    /* cutoff */
} pam_handle_t;

#define PAM_SILENT 0x8000U
#define PAM_DISALLOW_NULL_AUTHTOK 0x0001U
#define PAM_ESTABLISH_CRED 0x0002U
#define PAM_DELETE_CRED 0x0004U
#define PAM_REINITIALIZE_CRED 0x0008U
#define PAM_REFRESH_CRED 0x0010U
#define PAM_CHANGE_EXPIRED_AUTHTOK 0x0020U

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE (unsigned int)2048
#endif

typedef char small_str[16];
typedef char heap_buffer_t[MAX_BUF_SIZE];

typedef struct {
    heap_buffer_t buffer;
    size_t taken;
} heap_t;


#define SMALL_STR_SIZE \
    sizeof(small_str)

#define HEAP_SIZE \
    (sizeof(((heap_t*)NULL)->buffer))
#define FREE_HEAP_SIZE(HEAP) \
    (HEAP_SIZE - (HEAP)->taken)

BPF_RINGBUF_OUTPUT(OUTPUT, 8);

typedef enum {
    AUTH,
    SETCRED,
    ACCT_MGMT,
    OPEN_SESSION,
    CLOSE_SESSION,
    CHAUTHTOK,
} info_type_t;

typedef struct {
    bool silent;
    bool disallow_null_authtok;
    bool establish_cred;
    bool delete_cred;
    bool reinitialize_cred;
    bool refresh_cred;
    bool change_expired_authtok;
} pam_flags_t;

typedef struct {
    u64 pid;
    char procname[TASK_COMM_LEN];
    pam_flags_t flags;
} generic_info_t;

typedef struct {
    generic_info_t info;
} pam_auth_info_t;

typedef struct {
    generic_info_t info;
} pam_setcred_info_t;

typedef struct {
    generic_info_t info;
} pam_acct_mgmt_info_t;

typedef struct {
    generic_info_t info;
} pam_open_session_info_t;

typedef struct {
    generic_info_t info;
} pam_close_session_info_t;

typedef struct {
    generic_info_t info;
} pam_chauthtok_info_t;

typedef struct {
    info_type_t type;
    union {
        pam_auth_info_t auth_info;
        pam_setcred_info_t setcred_info;
        pam_acct_mgmt_info_t acct_mgmt_info;
        pam_open_session_info_t open_session_info;
        pam_close_session_info_t close_session_info;
        pam_chauthtok_info_t chauthtok_info;
    };
    heap_t heap;
} output_info_t;

BPF_PERCPU_ARRAY(OUTPUT_INFO, output_info_t, 1);

static output_info_t* create_output_info(info_type_t type){
    int zero = 0;
    output_info_t *output_info = OUTPUT_INFO.lookup(&zero);
    if (!output_info){
        return output_info;
    }
    generic_info_t info = {};

    bpf_get_current_comm(
        info.procname,
        sizeof(info.procname)
    );

    output_info->type = type;
    output_info->heap.taken = 0;

    info.pid = bpf_get_current_pid_tgid() >> 32;
    info.flags.silent = false;
    info.flags.disallow_null_authtok = false;
    info.flags.establish_cred = false;
    info.flags.delete_cred = false;
    info.flags.reinitialize_cred = false;
    info.flags.refresh_cred = false;
    info.flags.change_expired_authtok = false;

    switch(type){
        case AUTH:
            output_info->auth_info.info = info;
            break;
        case SETCRED:
            output_info->setcred_info.info = info;
            break;
        case ACCT_MGMT:
            output_info->acct_mgmt_info.info = info;
            break;
        case OPEN_SESSION:
            output_info->open_session_info.info = info;
            break;
        case CLOSE_SESSION:
            output_info->close_session_info.info = info;
            break;
        case CHAUTHTOK:
            output_info->chauthtok_info.info = info;
            break;
    }

    return output_info;
}

static pam_flags_t unpack_flags(int flags){
    pam_flags_t pam_flags = {
        .silent = flags & PAM_SILENT,
        .disallow_null_authtok = flags & PAM_DISALLOW_NULL_AUTHTOK,
        .establish_cred = flags & PAM_ESTABLISH_CRED,
        .delete_cred = flags & PAM_DELETE_CRED,
        .reinitialize_cred = flags & PAM_REINITIALIZE_CRED,
        .refresh_cred = flags & PAM_REFRESH_CRED,
        .change_expired_authtok = flags & PAM_CHANGE_EXPIRED_AUTHTOK
    };
    return pam_flags;
}

static void write_small_str_to_heap(heap_t *heap, small_str str) {
    if (heap->taken > HEAP_SIZE - SMALL_STR_SIZE){
        return;
    }
    strncpy(&heap->buffer[heap->taken], str, SMALL_STR_SIZE);
    heap->taken += strlen(str) + 1;
}

static void write_str_to_heap(
        heap_t *heap,
        const char *str) {
    const unsigned int space_per_record = 64;
    if (heap->taken > HEAP_SIZE - space_per_record){
        return;
    }

    int ret = bpf_probe_read_user_str(
        &heap->buffer[heap->taken],
        space_per_record,
        str
    );
    if (ret < 0){
        write_small_str_to_heap(heap, "%READ_ERROR%");
        return;
    }
    heap->taken += ret;
}

static void convert_heap_delimiters(heap_t *heap){
    const unsigned int border = MAX_BUF_SIZE;
    for (unsigned int i = 0; i < MAX_BUF_SIZE; i++){
        if (heap->buffer[i] == '\0' && i < heap->taken - 1){
            heap->buffer[i] = ' ';
        }
    }
}

static void parse_pam_argv(
        heap_t *heap,
        int argc,
        const char **argv){
    argc = argc > 10 ? 10 : argc;

    int available_space = HEAP_SIZE;
    write_small_str_to_heap(heap, "Module ARGV:");
    for (int i = 0; i < argc && available_space > 0; i++){
        write_str_to_heap(heap, argv[i]);
        available_space = HEAP_SIZE - heap->taken;
    }
}

static void parse_pam_handle(
        heap_t *heap,
        pam_handle_t *pamh){
    write_small_str_to_heap(heap, "authtok:");
    write_str_to_heap(heap, pamh->authtok);
    write_small_str_to_heap(heap, "oldauthtok:");
    write_str_to_heap(heap, pamh->oldauthtok);
    write_small_str_to_heap(heap, "prompt:");
    write_str_to_heap(heap, pamh->prompt);
    write_small_str_to_heap(heap, "service_name:");
    write_str_to_heap(heap, pamh->service_name);
    write_small_str_to_heap(heap, "user:");
    write_str_to_heap(heap, pamh->user);
    write_small_str_to_heap(heap, "rhost:");
    write_str_to_heap(heap, pamh->rhost);
    write_small_str_to_heap(heap, "ruser:");
    write_str_to_heap(heap, pamh->ruser);
    write_small_str_to_heap(heap, "tty:");
    write_str_to_heap(heap, pamh->tty);
    write_small_str_to_heap(heap, "xdisplay:");
    write_str_to_heap(heap, pamh->xdisplay);
    write_small_str_to_heap(heap, "authtok_type:");
    write_str_to_heap(heap, pamh->authtok_type);
}


int probe_pam_sm_authenticate(
        struct pt_regs *ctx,
        pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t *info = create_output_info(AUTH);
    if (!info){
        return 0;
    }
    info->auth_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_handle(&info->heap, pamh);
    convert_heap_delimiters(&info->heap);
    OUTPUT.ringbuf_output(info, sizeof(output_info_t), 0);
    return 0;
}

int probe_pam_sm_setcred(
        struct pt_regs *ctx,
        pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t *info = create_output_info(SETCRED);
    if (!info){
        return 0;
    }
    info->setcred_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_handle(&info->heap, pamh);
    convert_heap_delimiters(&info->heap);
    OUTPUT.ringbuf_output(info, sizeof(output_info_t), 0);
    return 0;
}

int probe_pam_sm_acct_mgmt(
        struct pt_regs *ctx,
        pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t *info = create_output_info(ACCT_MGMT);
    if (!info){
        return 0;
    }
    info->acct_mgmt_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_handle(&info->heap, pamh);
    convert_heap_delimiters(&info->heap);
    OUTPUT.ringbuf_output(info, sizeof(output_info_t), 0);
    return 0;
}

int probe_pam_sm_open_session(
        struct pt_regs *ctx,
        pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t *info = create_output_info(OPEN_SESSION);
    if (!info){
        return 0;
    }
    info->open_session_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_handle(&info->heap, pamh);
    convert_heap_delimiters(&info->heap);
    OUTPUT.ringbuf_output(info, sizeof(output_info_t), 0);
    return 0;
}

int probe_pam_sm_close_session(
        struct pt_regs *ctx,
        pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t *info = create_output_info(CLOSE_SESSION);
    if (!info){
        return 0;
    }
    info->close_session_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_handle(&info->heap, pamh);
    convert_heap_delimiters(&info->heap);
    OUTPUT.ringbuf_output(info, sizeof(output_info_t), 0);
    return 0;
}

int probe_pam_sm_chauthtok(
        struct pt_regs *ctx,
        pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t *info = create_output_info(CHAUTHTOK);
    if (!info){
        return 0;
    }
    info->chauthtok_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_handle(&info->heap, pamh);
    convert_heap_delimiters(&info->heap);
    OUTPUT.ringbuf_output(info, sizeof(output_info_t), 0);
    return 0;
}
'''


class pam_flags_t(ctypes.Structure):
    __slots__ = [
        'silent',
        'disallow_null_authtok',
        'establish_cred',
        'delete_cred',
        'reinitialize_cred',
        'refresh_cred',
        'change_expired_authtok',
    ]
    _fields_ = [
        ('silent', ctypes.c_bool),
        ('disallow_null_authtok', ctypes.c_bool),
        ('establish_cred', ctypes.c_bool),
        ('delete_cred', ctypes.c_bool),
        ('reinitialize_cred', ctypes.c_bool),
        ('refresh_cred', ctypes.c_bool),
        ('change_expired_authtok', ctypes.c_bool),
    ]


class generic_info_t(ctypes.Structure):
    __slots__ = [
        'pid',
        'procname',
        'flags',
    ]
    _fields_ = [
        ('pid', ctypes.c_uint64),
        ('procname', ctypes.c_char * 16),
        ('flags', pam_flags_t),
    ]


class pam_auth_info_t(ctypes.Structure):
    __slots__ = [
        'info',
    ]
    _fields_ = [
        ('info', generic_info_t),
    ]


class pam_setcred_info_t(ctypes.Structure):
    __slots__ = [
        'info',
    ]
    _fields_ = [
        ('info', generic_info_t),
    ]


class pam_acct_mgmt_info_t(ctypes.Structure):
    __slots__ = [
        'info',
    ]
    _fields_ = [
        ('info', generic_info_t),
    ]


class pam_open_session_info_t(ctypes.Structure):
    __slots__ = [
        'info',
    ]
    _fields_ = [
        ('info', generic_info_t),
    ]


class pam_close_session_info_t(ctypes.Structure):
    __slots__ = [
        'info',
    ]
    _fields_ = [
        ('info', generic_info_t),
    ]


class pam_chauthtok_info_t(ctypes.Structure):
    __slots__ = [
        'info',
    ]
    _fields_ = [
        ('info', generic_info_t),
    ]


class output_info_UNION(ctypes.Union):
    __slots__ = [
        'auth_info',
        'setcred_info',
        'acct_mgmt_info',
        'open_session_info',
        'close_session_info',
        'chauthtok_info'
    ]
    _fields_ = [
        ('auth_info', pam_auth_info_t),
        ('setcred_info', pam_setcred_info_t),
        ('acct_mgmt_info', pam_acct_mgmt_info_t),
        ('open_session_info', pam_open_session_info_t),
        ('close_session_info', pam_close_session_info_t),
        ('chauthtok_info', pam_chauthtok_info_t),
    ]


AUTH = 0
SETCRED = (AUTH + 1)
ACCT_MGMT = (SETCRED + 1)
OPEN_SESSION = (ACCT_MGMT + 1)
CLOSE_SESSION = (OPEN_SESSION + 1)
CHAUTHTOK = (CLOSE_SESSION + 1)


parser = argparse.ArgumentParser()
parser.add_argument(
    '-S', '--max-buffer-size',
    default=2048,
    type=int,
    help='change buffer for data capture (default 2048 bytes)'
)
parser.add_argument(
    '-d', '--pam-dir',
    default='/lib64/security/',
    type=Path,
    help='PAM-modules folder (default /lib64/security/)'
)
parser.add_argument(
    '-g', '--glob',
    default='pam_*.so',
    type=str,
    help='Glob for attaching subset of PAM-modules (default pam_*.so)'
)

args = parser.parse_args()
MAX_BUF_SIZE = args.max_buffer_size

COMPILED_BPF = BPF(text=PROGRAM, cflags=[f'-DMAX_BUF_SIZE=(unsigned int){MAX_BUF_SIZE}'])


class heap_t(ctypes.Structure):
    __slots__ = [
        'buffer',
        'taken',
    ]
    _fields_ = [
        ('buffer', ctypes.c_char * MAX_BUF_SIZE),
        ('taken', ctypes.c_size_t),
    ]


class output_info_t(ctypes.Structure):
    __slots__ = [
        'type',
        'heap',
    ]
    _anonymous_ = ('u',)
    _fields_ = [
        ('type', ctypes.c_int),
        ('u', output_info_UNION),
        ('heap', heap_t),
    ]


UPROBED_FUNCTONS = {
    AUTH: 'authenticate',
    SETCRED: 'setcred',
    ACCT_MGMT: 'acct_mgmt',
    OPEN_SESSION: 'open_session',
    CLOSE_SESSION: 'close_session',
    CHAUTHTOK: 'chauthtok'
}


def attach(bpf, library, pid=-1):
    for func in UPROBED_FUNCTONS.values():
        try:
            bpf.attach_uprobe(name=library,
                              sym=f'pam_sm_{func}',
                              fn_name=f'probe_pam_sm_{func}',
                              pid=pid)
        except Exception:
            continue


def generic_info(generic_info: generic_info_t):
    proc_info = f'{generic_info.procname.decode()}({generic_info.pid})'
    flags_info = []
    for field in pam_flags_t.__slots__:
        flag = getattr(generic_info.flags, field)
        if flag:
            flags_info.append(f'+{field}')
    return [proc_info, f"[{' '.join(flags_info)}]"]


def auth_info(auth_info: pam_auth_info_t):
    generic_info_list = generic_info(auth_info.info)
    return generic_info_list


def setcred_info(setcred_info: pam_setcred_info_t):
    return generic_info(setcred_info.info)


def acct_mgmt_info(acct_mgmt_info: pam_acct_mgmt_info_t):
    return generic_info(acct_mgmt_info.info)


def open_session_info(open_session_info: pam_open_session_info_t):
    return generic_info(open_session_info.info)


def close_session_info(close_session_info: pam_close_session_info_t):
    return generic_info(close_session_info.info)


def chauthtok_info(chauthtok_info: pam_chauthtok_info_t):
    return generic_info(chauthtok_info.info)


def print_event(cpu, data, size):
    info = ctypes.cast(data, ctypes.POINTER(output_info_t)).contents
    info_list = []
    if info.type == AUTH:
        info_list = auth_info(info.auth_info)
    elif info.type == SETCRED:
        info_list = setcred_info(info.setcred_info)
    elif info.type == ACCT_MGMT:
        info_list = acct_mgmt_info(info.acct_mgmt_info)
    elif info.type == OPEN_SESSION:
        info_list = open_session_info(info.open_session_info)
    elif info.type == CLOSE_SESSION:
        info_list = close_session_info(info.close_session_info)
    elif info.type == CHAUTHTOK:
        info_list = chauthtok_info(info.chauthtok_info)

    info_func = f'pam_sm_{UPROBED_FUNCTONS[info.type]}:'
    heap_info = ''
    if info.heap.taken:
        heap_info = info.heap.buffer.decode()
    print(' '.join([info_func] + info_list + [heap_info]), file=sys.stderr)


for module in args.pam_dir.glob(args.glob):
    attach(COMPILED_BPF, str(module))

COMPILED_BPF['OUTPUT'].open_ring_buffer(print_event)

print('Ready')
while 1:
    try:
        COMPILED_BPF.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
