#!/usr/bin/env python

import sys
import ctypes

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

#define PAM_SILENT 0x8000U
#define PAM_DISALLOW_NULL_AUTHTOK 0x0001U
#define PAM_ESTABLISH_CRED 0x0002U
#define PAM_DELETE_CRED 0x0004U
#define PAM_REINITIALIZE_CRED 0x0008U
#define PAM_REFRESH_CRED 0x0010U
#define PAM_CHANGE_EXPIRED_AUTHTOK 0x0020U

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE 2048
#endif

typedef char heap_t[MAX_BUF_SIZE];

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
    int heap_size;
    heap_t *heap;
} output_info_t;

BPF_PERCPU_ARRAY(HEAP, heap_t, 1);

static output_info_t create_output_info(info_type_t type){
    int zero = 0;
    output_info_t output_info = {};
    generic_info_t info = {};

    bpf_get_current_comm(
        info.procname,
        sizeof(info.procname)
    );

    output_info.type = type;
    output_info.heap = HEAP.lookup(&zero);
    output_info.heap_size = sizeof(heap_t);

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
            output_info.auth_info.info = info;
            break;
        case SETCRED:
            output_info.setcred_info.info = info;
            break;
        case ACCT_MGMT:
            output_info.acct_mgmt_info.info = info;
            break;
        case OPEN_SESSION:
            output_info.open_session_info.info = info;
            break;
        case CLOSE_SESSION:
            output_info.close_session_info.info = info;
            break;
        case CHAUTHTOK:
            output_info.chauthtok_info.info = info;
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

static void parse_pam_argv(output_info_t *info, int argc, const char **argv){
    if (!info->heap){
        return;
    }

    argc = argc > 10 ? 10 : argc;

    int bytes_written = 0;
    int available_space = info->heap_size;
    const unsigned int space_per_record = 64;
    for (int i = 0; i < argc && available_space > 0; i++){
        int ret = bpf_probe_read_kernel_str(
            *(info->heap)+bytes_written,
            space_per_record,
            argv[i]
        );
        if (ret < 0){
            break;
        }
        bytes_written += ret;
        available_space = info->heap_size - bytes_written;
    }
}

int probe_pam_sm_authenticate(
        struct pt_regs *ctx,
        void *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t info = create_output_info(AUTH);
    info.auth_info.info.flags = unpack_flags(flags);
    parse_pam_argv(&info, argc, argv);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
    return 0;
}

int probe_pam_sm_setcred(
        struct pt_regs *ctx,
        void *pamh,
        int flags){
    output_info_t info = create_output_info(SETCRED);
    info.setcred_info.info.flags = unpack_flags(flags);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
    return 0;
}

int probe_pam_sm_acct_mgmt(
        struct pt_regs *ctx,
        void *pamh,
        int flags){
    output_info_t info = create_output_info(ACCT_MGMT);
    info.acct_mgmt_info.info.flags = unpack_flags(flags);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
    return 0;
}

int probe_pam_sm_open_session(
        struct pt_regs *ctx,
        void *pamh,
        int flags){
    output_info_t info = create_output_info(OPEN_SESSION);
    info.open_session_info.info.flags = unpack_flags(flags);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
    return 0;
}

int probe_pam_sm_close_session(
        struct pt_regs *ctx,
        void *pamh,
        int flags){
    output_info_t info = create_output_info(CLOSE_SESSION);
    info.close_session_info.info.flags = unpack_flags(flags);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
    return 0;
}

int probe_pam_sm_chauthtok(
        struct pt_regs *ctx,
        void *pamh,
        int flags){
    output_info_t info = create_output_info(CHAUTHTOK);
    info.chauthtok_info.info.flags = unpack_flags(flags);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
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

MAX_BUF_SIZE = 2048


class output_info_t(ctypes.Structure):
    __slots__ = [
        'type',
        'heap_size',
        'heap',
    ]
    _anonymous_ = ('u',)
    _fields_ = [
        ('type', ctypes.c_int),
        ('u', output_info_UNION),
        ('heap_size', ctypes.c_int),
        ('heap', ctypes.c_char * MAX_BUF_SIZE),
    ]


UPROBED_FUNCTONS = {
    AUTH: 'authenticate',
    SETCRED: 'setcred',
    ACCT_MGMT: 'acct_mgmt',
    OPEN_SESSION: 'open_session',
    CLOSE_SESSION: 'close_session',
    CHAUTHTOK: 'chauthtok'
}

bpf = BPF(text=PROGRAM, cflags=[f'-DMAX_BUF_SIZE={MAX_BUF_SIZE}'])


def attach(bpf, library, pid=-1):
    for func in UPROBED_FUNCTONS.values():
        bpf.attach_uprobe(name=library,
                          sym=f'pam_sm_{func}',
                          fn_name=f'probe_pam_sm_{func}',
                          pid=pid)


def generic_info(generic_info: generic_info_t):
    info_list = [str(generic_info.pid), generic_info.procname.decode()]
    flags_info = []
    for field in pam_flags_t.__slots__:
        flag = getattr(generic_info.flags, field)
        if flag:
            flags_info.append(f'+{field}')
        else:
            flags_info.append(f'-{field}')
    return info_list + [f"[{' '.join(flags_info)}]"]


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
    print(' '.join([info_func] + info_list + [repr(info.heap)]), file=sys.stderr)


attach(bpf, '/lib64/security/pam_env.so')
bpf['OUTPUT'].open_ring_buffer(print_event)

while 1:
    try:
        bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
