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
} output_info_t;

static output_info_t create_output_info(info_type_t type){
    output_info_t output_info = {.type = type};
    generic_info_t info = {};

    bpf_get_current_comm(
        info.procname,
        sizeof(info.procname)
    );

    info.pid = bpf_get_current_pid_tgid() >> 32;
    info.flags.silent = "";
    info.flags.disallow_null_authtok = "";
    info.flags.establish_cred = "";
    info.flags.delete_cred = "";
    info.flags.reinitialize_cred = "";
    info.flags.refresh_cred = "";
    info.flags.change_expired_authtok = "";

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

int probe_pam_sm_authenticate(
        struct pt_regs *ctx,
        void *pamh,
        int flags,
        int argc,
        const char **argv){
    output_info_t info = create_output_info(AUTH);
    info.auth_info.info.flags = unpack_flags(flags);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);
    return 0;
}

int probe_pam_sm_setcred(struct pt_regs *ctx){
    output_info_t info = create_output_info(SETCRED);
    info.setcred_info.info.flags = unpack_flags(0);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);

    return 0;
}

int probe_pam_sm_acct_mgmt(struct pt_regs *ctx){
    output_info_t info = create_output_info(ACCT_MGMT);
    info.acct_mgmt_info.info.flags = unpack_flags(0);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);

    return 0;
}

int probe_pam_sm_open_session(struct pt_regs *ctx){
    output_info_t info = create_output_info(OPEN_SESSION);
    info.open_session_info.info.flags = unpack_flags(0);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);

    return 0;
}

int probe_pam_sm_close_session(struct pt_regs *ctx){
    output_info_t info = create_output_info(CLOSE_SESSION);
    info.close_session_info.info.flags = unpack_flags(0);
    OUTPUT.ringbuf_output(&info, sizeof(info), 0);

    return 0;
}

int probe_pam_sm_chauthtok(struct pt_regs *ctx){
    output_info_t info = create_output_info(CHAUTHTOK);
    info.chauthtok_info.info.flags = unpack_flags(0);
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


class output_info_t(ctypes.Structure):
    __slots__ = [
        'type',
    ]
    _anonymous_ = ('u',)
    _fields_ = [
        ('type', ctypes.c_int),
        ('u', output_info_UNION),
    ]


UPROBED_FUNCTONS = [
    'authenticate',
    'setcred',
    'acct_mgmt',
    'open_session',
    'close_session',
    'chauthtok'
]

bpf = BPF(text=PROGRAM)


def attach(bpf, library, pid=-1):
    for func in UPROBED_FUNCTONS:
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
    return info_list + [f" [{' '.join(flags_info)}]"]


def auth_info(auth_info: pam_auth_info_t):
    return ['pam_sm_authenticate:'] + generic_info(auth_info.info)


def setcred_info(setcred_info: pam_setcred_info_t):
    return ['pam_sm_setcred:'] + generic_info(setcred_info.info)


def acct_mgmt_info(acct_mgmt_info: pam_acct_mgmt_info_t):
    return ['pam_sm_acct_mgmt:'] + generic_info(acct_mgmt_info.info)


def open_session_info(open_session_info: pam_open_session_info_t):
    return ['pam_sm_open_session:'] + generic_info(open_session_info.info)


def close_session_info(close_session_info: pam_close_session_info_t):
    return ['pam_sm_close_session:'] + generic_info(close_session_info.info)


def chauthtok_info(chauthtok_info: pam_chauthtok_info_t):
    return ['pam_sm_chauthtok:'] + generic_info(chauthtok_info.info)


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

    print(' '.join(info_list), file=sys.stderr)


attach(bpf, '/lib64/security/pam_unix.so')
bpf['OUTPUT'].open_ring_buffer(print_event)

while 1:
    try:
        bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
