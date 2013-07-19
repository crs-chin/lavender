/*
 * jni_javender.c
 * Copyright (C) 2013  Crs Chin <crs.chin@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#define LOG_TAG "JAVENDER"
 
#include <utils/Log.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>  
#include <pthread.h>
#include <time.h>

#include "util.h"
#include "desert.h"
#include "jni.h"
#include "JNIHelp.h"

#ifndef CONFIG_STAT_PATH
#define CONFIG_STAT_PATH CONFIG_STAT_DIR CONFIG_STAT_FILE
#endif

#define JAVENDER_F_INIT 1
#define JAVENDER_F_CONNECT (1<<1)
#define JAVENDER_F_FRONT_END (1<<2)

typedef struct _verdict_info verdict_info;

struct _verdict_info{
    list list;
    msg_verdict_req req;
};


static JavaVM *java_vm = NULL;

static int javender_state = 0;

#define JAVENDER_STATE(s) (javender_state & JAVENDER_F_##s)
#define JAVENDER_SET(s) do{javender_state |= JAVENDER_F_##s;}while(0)
#define JAVENDER_CLEAR(s) do{javender_state &= ~JAVENDER_F_##s;}while(0)

static pthread_mutex_t verdict_lock = PTHREAD_MUTEX_INITIALIZER;
static list verdict_list = LIST_HEAD_INIT(verdict_list);

static jobject on_connect = NULL;
static jobject on_verdict = NULL;
static jobject on_msg = NULL;
static const char *javender_msg = "Javender, the Java binding library";

#if 0
static pthread_mutex_t __lock = PTHREAD_MUTEX_INITIALIZER;

static inline void lock(void)
{
    pthread_mutex_lock(&__lock);
}

static inline void unlock(void)
{
    pthread_mutex_unlock(&__lock);
}
#else
static inline void lock(void) {}
static inline void unlock(void) {}
#endif

static verdict_info *verdict_info_alloc(const msg_verdict_req *req)
{
    verdict_info *info;
    const msg_fd_owner *fo;
    size_t payload = sizeof(msg_fd_owner) * req->fo_count;

    msg_fd_owner_for_each(fo, req)  {
        payload += strlen(fo->exe) + 1;
    }list_end;
    if((info = new_instance_ex(verdict_info, payload)))  {
        list_init(&info->list);
        memcpy(&info->req, req, sizeof(*req) + payload);
    }
    return info;
}

static inline void verdict_purge(void)
{
    verdict_info *iter, *n;

    pthread_mutex_lock(&verdict_lock);
    list_for_each_entry_safe(iter, n, &verdict_list, list)  {
        list_delete(&iter->list);
        free(iter);
    }
    pthread_mutex_unlock(&verdict_lock);
}

static inline JNIEnv *get_env(void)
{
    JNIEnv *env = NULL;

    (*java_vm)->AttachCurrentThread(java_vm, &env, NULL);
    return env;
}

static void on_connect_cb(int state, unsigned int peer, void *ud)
{
    JNIEnv *env = get_env();
    jclass cls;
    jmethodID method;

    if(! state)
        verdict_purge();

    lock();
    ALOGI("connection status change:%d %d", state, peer);
    if(state)  {
        JAVENDER_SET(CONNECT);
    }else  {
        JAVENDER_CLEAR(FRONT_END);
        JAVENDER_CLEAR(CONNECT);
        desert_disconnect();
    }
    if(on_connect)  {
        if(! (cls = (*env)->GetObjectClass(env, on_connect)))  {
            ALOGE("can't get OnConnect object class");
        }else  {
            if((method = (*env)->GetMethodID(env, cls, "onConnect", "(II)V")))  {
                //ALOGI("call java onConnect method");
                (*env)->CallVoidMethod(env, on_connect, method, state, peer);
            }else  {
                ALOGE("unable to find java onConnect method");
            }
        }
    }
    unlock();
}

static jbyteArray __from_u64(JNIEnv *env, uint64_t u)
{
    jbyteArray ret = NULL;
    jbyteArray a = (*env)->NewByteArray(env, sizeof(u));
    const jbyte *p = (const jbyte *)&u;

    if(a)  {
        (*env)->SetByteArrayRegion(env, a, 0, sizeof(u), p);
        if((ret = (*env)->NewGlobalRef(env, a)))
            (*env)->DeleteLocalRef(env, a);
    }
    return ret;
}


static void __request_verdict(const msg_verdict_req *req)
{
    JNIEnv *env = get_env();
    jclass cls;
    jmethodID method;
    jbyteArray rid;
    jintArray pid;
    jintArray uid;
    jobjectArray exe;
    const msg_fd_owner *fo;
    jsize i = 0;
    struct timespec ts;
    time_t t = time(NULL);

    if(on_verdict)  {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        t += req->ts.tv_sec - ts.tv_sec;
        rid = __from_u64(env, req->id);
        pid = (*env)->NewIntArray(env, req->fo_count);
        uid = (*env)->NewIntArray(env, req->fo_count);
        exe = (*env)->NewObjectArray(env, req->fo_count, 
                                     (*env)->FindClass(env, "java/lang/String"),
                                     (*env)->NewStringUTF(env, ""));
        msg_fd_owner_for_each(fo, req)  {
            (*env)->SetIntArrayRegion(env, pid, i, 1, (jint *)&fo->pid);
            (*env)->SetIntArrayRegion(env, uid, i, 1, (jint *)&fo->euid);
            (*env)->SetObjectArrayElement(env, exe, i,
                                          (*env)->NewStringUTF(env, fo->exe));
            i++;
        }list_end;
        if(! (cls = (*env)->GetObjectClass(env, on_verdict)))  {
            ALOGE("can't find OnVerdict object class");
        }else  {
            if((method = (*env)->GetMethodID(env, cls, "onVerdict", "([B[I[I[Ljava/lang/String;J)V")))  {
                //ALOGI("call java onVerdict method");
                (*env)->CallVoidMethod(env, on_verdict, method, rid, pid, uid, exe, t);
            }else  {
                ALOGE("unable to find java onVerdict method");
            }
        }
        (*env)->DeleteLocalRef(env, rid);
        (*env)->DeleteLocalRef(env, pid);
        (*env)->DeleteLocalRef(env, uid);
        (*env)->DeleteLocalRef(env, exe);
    }
}

static void verdict_enqueue(verdict_info *info)
{
    verdict_info *iter, *n;
    struct timespec ts;
    int req_now;

    pthread_mutex_lock(&verdict_lock);
    if(! (req_now = list_empty(&verdict_list)))  {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        list_for_each_entry_safe(iter, n, &verdict_list, list)  {
            /* clear expired pending verdicts */
            if(ts_cmp(&ts, &iter->req.ts) >= 0)  {
                req_now = 1;
                list_delete(&iter->list);
                free(iter);
            }
        }
    }
    list_append(&verdict_list, &info->list);
    if(req_now)  {
        info = list_entry(verdict_list.l_nxt, verdict_info, list);
        lock();
        __request_verdict(&info->req);
        unlock();
    }
    pthread_mutex_unlock(&verdict_lock);
}

static void emit_info(const msg_runtime_info *info)
{
    JNIEnv *env = get_env();
    jclass cls;
    jmethodID method;
    jbyteArray _msg, msg;
    const jbyte *b = (const jbyte *)info->info;

    if(on_msg)  {
        _msg = (*env)->NewByteArray(env, info->len);
        (*env)->SetByteArrayRegion(env, _msg, 0, info->len, b);
        if((msg = (*env)->NewGlobalRef(env, _msg))
           && (cls = (*env)->GetObjectClass(env, on_msg))
           && (method = (*env)->GetMethodID(env, cls, "onMsg", "(IJ[B)V")))  {
            (*env)->CallVoidMethod(env, on_msg, method, info->type, (jlong)info->time, msg);
        }
        (*env)->DeleteLocalRef(env, _msg);
    }
}

static void on_verdict_cb(int type, const void *msg, void *ud)
{
    switch(type)  {
    case CACTUS_VERDICT_REQUEST:  {
        verdict_info *info;

        if((info = verdict_info_alloc((const msg_verdict_req *)msg)))
            verdict_enqueue(info);
        break;
    }
    case CACTUS_RUNTIME_INFO:  {
        if(on_msg)
            emit_info((const msg_runtime_info *)msg);
        break;
    }
    default:
        ALOGE("unrecognized verdict type:%d", type);
        break;
    }
}

#define CONNECT_F_ABSTRACT 1
#define CONNECT_F_FRONT_END (1<<1)

static jboolean jni_connect(JNIEnv *env, jobject classz, jstring path, jint flags,
                            jobject onConnect, jobject onVerdict, jobject onMsg)
{
    int err = 0;

    lock();
    //ALOGI("jni_connect: flags(0x%X), onConnect(0x%X), onVerdict(0x%X)", flags, onConnect, onVerdict);
    if(! JAVENDER_STATE(INIT))  {
        if((err = desert_init(javender_msg, on_connect_cb, NULL))) {
            ALOGE("unable to initialized up desert:%d!", err);
            goto out;
        }
        JAVENDER_SET(INIT);
    }

    if(onConnect)
        on_connect = (*env)->NewGlobalRef(env, onConnect);
    if(onVerdict)
        on_verdict = (*env)->NewWeakGlobalRef(env, onVerdict);
    if(onMsg)
        on_msg = (*env)->NewWeakGlobalRef(env, onMsg);

    if(! JAVENDER_STATE(CONNECT))  {
        ALOGI("connecting to cactus back-end");
        if((err = desert_connect(NULL, NULL, 0)))  {
            ALOGE("unable to connect the cactus:%d", err);
            goto out;
        }
    }
    JAVENDER_SET(CONNECT);

    if(flags & CONNECT_F_FRONT_END)  {
        //ALOGI("check registering as front-end");
        if(! JAVENDER_STATE(FRONT_END))  {
            ALOGI("self registering as front-end");
            if((err = desert_register_fe(0, on_verdict_cb, env)))  {
                ALOGE("unable to self register as front-end:%d", err);
                desert_disconnect();
                JAVENDER_CLEAR(CONNECT);
                goto out;
            }
        }
        JAVENDER_SET(FRONT_END);
    }
 out:
    if(err)  {
        if(on_connect)  {
            (*env)->DeleteGlobalRef(env, on_connect);
            on_connect = NULL;
        }
        if(on_verdict)  {
            (*env)->DeleteGlobalRef(env, on_verdict);
            on_verdict = NULL;
        }
    }
    ALOGI("lavender service connect %s", err ? "fail" : "success");
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static void jni_disconnect(JNIEnv *env, jobject classz)
{
    lock();
    if(JAVENDER_STATE(CONNECT))  {
        desert_disconnect();
        JAVENDER_CLEAR(CONNECT);
        JAVENDER_CLEAR(FRONT_END);
    }
    unlock();
}

static jint jni_get_cactus_state(JNIEnv *env, jobject classz)
{
    jint st = -1;

    lock();
    if(JAVENDER_STATE(CONNECT))
        st = desert_cactus_status();
    unlock();
    return st;
}

static jboolean jni_set_cactus_state(JNIEnv *env, jobject classz, jint state)
{
    int err = -1;

    lock();
    if(JAVENDER_STATE(CONNECT))  {
        if((err = desert_switch_cactus(state)))
            ALOGE("failure switching cactus status:%d", err);
    }
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static inline int __from_array(JNIEnv *env, jbyteArray a, uint64_t *id)
{
    jbyte *p;

    if((*env)->GetArrayLength(env, a) != sizeof(*id))
        return -1;
    if((p = (*env)->GetByteArrayElements(env, a, NULL)))  {
        *id = *(uint64_t *)p;
        (*env)->ReleaseByteArrayElements(env, a, p, JNI_ABORT);
        return 0;
    }
    return -1;
}

static void verdict_refresh(void)
{
    verdict_info *info = NULL, *iter, *n;
    struct timespec ts;

    pthread_mutex_lock(&verdict_lock);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    list_for_each_entry_safe(iter, n, &verdict_list, list)  {
        if(ts_cmp(&ts, &iter->req.ts) < 0)  {
            info = iter;
            break;
        }
        list_delete(&iter->list);
        free(info);
    }
    if(info)  {
        lock();
        __request_verdict(&info->req);
        unlock();
    }
    pthread_mutex_unlock(&verdict_lock);
}

static jboolean jni_send_verdict(JNIEnv *env, jobject classz, jbyteArray rid, jint verd)
{
    verdict_info *info, *n;
    uint64_t id = 0;
    int err = -1;

    if(! (err = __from_array(env, rid, &id)))  {
        pthread_mutex_lock(&verdict_lock);
        if(list_empty(&verdict_list))
            ALOG_ASSERT(env, "verdict list unexpected empty!");
        info = list_entry(verdict_list.l_nxt, verdict_info, list);
        if(info->req.id == id)  {
            list_delete(&info->list);
            free(info);
        }
        pthread_mutex_unlock(&verdict_lock);

        lock();
        if(JAVENDER_STATE(CONNECT))  {
            if(! err && verd != VERDICT_NONE)
                err = desert_send_verdict(id, verd);
            ALOGI("sent verdict ID:%llu verd:%u", id, verd);
        }
        unlock();

        verdict_refresh();
    }
    return err ? JNI_FALSE : JNI_TRUE;
}

static jboolean jni_load_rules(JNIEnv *env, jobject classz, jstring path)
{
    int err = -1;
    const char *p;

    lock();
    if(JAVENDER_STATE(CONNECT))  {
        if((p = (*env)->GetStringUTFChars(env, path, NULL)))
            err = desert_load_rules(p);
        ALOGI("load rules from \"%s\":%d", p ?: "<NULL>", err);
        if(p)
            (*env)->ReleaseStringUTFChars(env, path, p);
    }
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static jboolean jni_dump_rules(JNIEnv *env, jobject classz, jstring path)
{
    int err = -1;
    const char *p;

    lock();
    if(JAVENDER_STATE(CONNECT))  {
        if((p = (*env)->GetStringUTFChars(env, path, NULL)))
            err = desert_dump_rules(p);
        ALOGI("load rules from \"%s\":%d", p ?: "<NULL>", err);
        if(p)
            (*env)->ReleaseStringUTFChars(env, path, p);
    }
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static jstring jni_version_info(JNIEnv *env, jobject classz)
{
    jstring info = NULL;
    const char *p;

    lock();
    if(JAVENDER_STATE(CONNECT))  {
        if((p = desert_cactus_version(NULL)))
            info = (*env)->NewStringUTF(env, p);
    }
    unlock();
    return info;
}

static jboolean jni_flush_logs(JNIEnv *env, jobject classz)
{
    int err = -1;

    lock();
    if(JAVENDER_STATE(CONNECT))
        err = desert_flush_logs();
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static jboolean jni_set_log_type_enable(JNIEnv *env, jobject classz, jint type, jboolean state)
{
    int err = -1;

    lock();
    if(JAVENDER_STATE(CONNECT))
        err = desert_log_set_type_enabled(type, state);
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static jboolean jni_set_log_level_enable(JNIEnv *env, jobject classz, jint level, jboolean state)
{
    int err = -1;

    lock();
    if(JAVENDER_STATE(CONNECT))
        err = desert_log_set_level_enabled(level, state);
    unlock();
    return err ? JNI_FALSE : JNI_TRUE;
}

static jboolean jni_get_log_type_enable(JNIEnv *env, jobject classz, jint type)
{
    msg_log_stat st;
    jboolean ret = JNI_FALSE;

    lock();
    if(JAVENDER_STATE(CONNECT)
       && type >= 0
       && type < NUM_LOG)  {
        if(! desert_log_state(&st))
            ret = st.ctl[type] ? JNI_TRUE : JNI_FALSE;
    }
    lock();
    return ret;
}

static jboolean jni_get_log_level_enable(JNIEnv *env, jobject classz, jint level)
{
    msg_log_stat st;
    jboolean ret = JNI_FALSE;

    lock();
    if(JAVENDER_STATE(CONNECT)
       && level >= 0
       && level < NUM_LVL)  {
        if(! desert_log_state(&st))
            ret = st.ctl[level] ? JNI_TRUE : JNI_FALSE;
    }
    lock();
    return ret;
}

static void jni_shutdown(JNIEnv *env, jobject classz)
{
    lock();
    if(JAVENDER_STATE(CONNECT))
        desert_shutdown();
    unlock();
}

static jboolean jni_set_counter_enable(JNIEnv *env, jobject classz, jboolean enable)
{
    jboolean ret = JNI_FALSE;

    lock();
    if(JAVENDER_STATE(CONNECT) && ! desert_set_counter_enable(enable))
        ret = JNI_TRUE;
    unlock();
    return ret;
}

static jboolean jni_get_counter_enable(JNIEnv *env, jobject classz)
{
    jboolean ret = JNI_FALSE;

    lock();
    if(JAVENDER_STATE(CONNECT) && desert_get_counter_status() > 0)
        ret = JNI_TRUE;
    unlock();
    return ret;
}

static jint jni_check_cactus_status(JNIEnv *env, jobject classz)
{
    jint ret = 0;
    char buf[50] = "";

    lock();
    if(file_read(CONFIG_STAT_PATH, buf, sizeof(buf)) > 0
       && ! strcmp(buf, "AVAILABLE"))
        ret = 1;
    unlock();
    return ret;
}

static JNINativeMethod gMethods[] = {
    /* name, signature, funcPtr */
    {"__connect", "(Ljava/lang/String;ILcom/javender/Javender$OnConnectListener;"
     "Lcom/javender/Javender$OnVerdictListener;"
     "Lcom/javender/Javender$OnMsgListener;)Z", (void *)jni_connect,},
    {"__disconnect", "()V", (void *)jni_disconnect,},
    {"getCactusState", "()I", (void *)jni_get_cactus_state,},
    {"setCactusState", "(I)Z", (void *)jni_set_cactus_state,},
    {"sendVerdict", "([BI)Z", (void *)jni_send_verdict,},
    {"loadRules", "(Ljava/lang/String;)Z", (void *)jni_load_rules,},
    {"dumpRules", "(Ljava/lang/String;)Z", (void *)jni_dump_rules,},
    {"versionInfo", "()Ljava/lang/String;", (void *)jni_version_info,},
    {"flushLogs", "()Z", (void *)jni_flush_logs,},
    {"setLogTypeEnable", "(IZ)Z", (void *)jni_set_log_type_enable,},
    {"setLogLevelEnable", "(IZ)Z", (void *)jni_set_log_level_enable,},
    {"getLogTypeEnable", "(I)Z", (void *)jni_get_log_type_enable,},
    {"getLogLevelEnable", "(I)Z", (void *)jni_get_log_level_enable,},
    {"shutdown", "()V", (void *)jni_shutdown,},
    {"setCounterEnable", "(Z)Z", (void *)jni_set_counter_enable,},
    {"getCounterEnable", "()Z", (void *)jni_get_counter_enable,},
    {"checkCactusStatus", "()I", (void *)jni_check_cactus_status,},
};

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv* env = NULL;

    ALOGI("JAVENDER JNI_OnLoad");

    if((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
        ALOGE("GetEnv failed!");
        return -1;
    }
    ALOG_ASSERT(env, "Could not retrieve the env!");

    java_vm = vm;
    jniRegisterNativeMethods(env, "com/javender/Javender",
                             gMethods, arraysize(gMethods));
    return JNI_VERSION_1_4;
}


