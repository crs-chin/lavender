/*
 * desert_gtk.c
 * Copyright (C) 2012  Crs Chin <crs.chin@gmail.com>
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

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <gtk/gtk.h>

#include "msg_base.h"
#include "desert_gtk.h"

#define TIMER_MIN 5

typedef struct _verdict_req verdict_req;
typedef struct _verdict_obj verdict_obj;

struct _verdict_obj{
    uid_t uid, gid;
    pid_t pid, ppid, sid;
    char *next;
    char exe[0];
};

struct _verdict_req{
    verdict_req *next;
    uint64_t id;
    struct timespec ts;
    time_t timer;
    verdict_obj objs[0];
};

enum{
    COL_TAG,
    COL_VALUE,

    NUM_COL,
};

static int __initialized = 0;

static pthread_mutex_t verdict_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t verdict_cond = PTHREAD_COND_INITIALIZER;
static pthread_t verdict_thread = 0;

static int verdict_emit = 0;    /* set to 1 if verdict window's waiting */
static on_verdict verdict_cb = NULL;
static void *verdict_cb_ud = NULL;
static verdict_req *verdict_current = NULL;
static verdict_req *verdict_list = NULL;
static verdict_req **verdict_list_end = &verdict_list;
static guint verdict_timer = 0;

static GtkWidget *verdict_win = NULL;
static GtkBuilder *verdict_builder = NULL;
static GtkWidget *always_toggle = NULL;

#define __INSERT_ID(name,val)                                           \
    do{sprintf(id, "%d", val);                                          \
        gtk_tree_store_append(tree_store, &iter2, &iter1);              \
        gtk_tree_store_set(tree_store, &iter2, COL_TAG, name, COL_VALUE, id, -1); \
    }while(0)

#define verdict_obj_for_each(vobj,vreq)         \
    for(vobj = &vreq->objs[0]; vobj; vobj = (typeof(vobj))vobj->next)

static int __setup_window(const verdict_req *vreq)
{
    static GtkTreeStore *tree_store = NULL;
    static GtkWidget *tree = NULL;
    GtkTreeIter iter1, iter2;
    const verdict_obj *vobj;
    char id[20];

    if(! tree_store)  {
        GtkTreeStore *store;
        GtkCellRenderer *render;
        GtkTreeViewColumn *col;

        if(! (tree = GTK_WIDGET(gtk_builder_get_object(verdict_builder, "proglist"))))  {
            g_print("unable to get tree view!\n");
            return -1;
        }

        store = gtk_tree_store_new(NUM_COL, G_TYPE_STRING, G_TYPE_STRING);
        gtk_tree_view_set_model(GTK_TREE_VIEW(tree), GTK_TREE_MODEL(store));

        render = gtk_cell_renderer_text_new();
        col = gtk_tree_view_column_new_with_attributes("", render,
                                                       "text", COL_TAG, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);

        render = gtk_cell_renderer_text_new();
        col = gtk_tree_view_column_new_with_attributes("", render,
                                                       "text", COL_VALUE, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);

        tree_store = store;
    }

    gtk_tree_store_clear(tree_store);
    verdict_obj_for_each(vobj, vreq)  {
        gtk_tree_store_append(tree_store, &iter1, NULL);
        gtk_tree_store_set(tree_store, &iter1, COL_TAG, vobj->exe, -1);

        __INSERT_ID("User ID", vobj->uid);
        __INSERT_ID("Group ID", vobj->gid);
        __INSERT_ID("PID", vobj->pid);
        __INSERT_ID("Parent PID", vobj->ppid);
        __INSERT_ID("Session ID", vobj->sid);
    }
    gtk_tree_view_expand_all(GTK_TREE_VIEW(tree));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(always_toggle), FALSE);

    return 0;
}

static inline void __set_label(time_t val)
{
    GtkLabel *label = GTK_LABEL(gtk_builder_get_object(verdict_builder, "timer"));;
    gchar *markup = g_markup_printf_escaped ("<span style=\"italic\">Close in %" PRIu64 " second(s)</span>", val);

    if(label)
        gtk_label_set_markup(label, markup);
    g_free (markup);
}

static gboolean timer_tick(gpointer data)
{
    time_t ts = time(NULL), t = -1;

    pthread_mutex_lock(&verdict_lock);
    if(verdict_current)
        t = verdict_current->timer;
    pthread_mutex_unlock(&verdict_lock);
    if(t == (time_t)-1 || ts >= t)  {
        gdk_threads_enter();
        gtk_widget_hide_all(verdict_win);
        gdk_threads_leave();

        pthread_mutex_lock(&verdict_lock);
        verdict_emit = 0;
        verdict_timer = 0;
        pthread_cond_broadcast(&verdict_cond);
        pthread_mutex_unlock(&verdict_lock);
        return FALSE;
    }

    gdk_threads_enter();
    __set_label(t - ts);
    gdk_threads_leave();
    return TRUE;
}

static inline int ts_cmp(const struct timespec *a, const struct timespec *b)
{
    if(a->tv_sec < b->tv_sec)
        return -1;
    else if(a->tv_sec > b->tv_sec)
        return 1;
    if(a->tv_nsec < b->tv_nsec)
        return -1;
    else if(a->tv_nsec > b->tv_nsec)
        return 1;
    return 0;
}

static void *desert_gtk_thread(void *arg)
{
    struct timespec ts;
    time_t timeout;

    for(;;)  {
        pthread_mutex_lock(&verdict_lock);
        do{
            while(verdict_emit)
                pthread_cond_wait(&verdict_cond, &verdict_lock);
            while(! verdict_list)
                pthread_cond_wait(&verdict_cond, &verdict_lock);
            if(verdict_current)  {
                free(verdict_current);
                verdict_current = NULL;
            }
            verdict_current = verdict_list;
            verdict_list = verdict_list->next;
            if(! verdict_list)
                verdict_list_end = &verdict_list;

            clock_gettime(CLOCK_MONOTONIC, &ts);
            if(ts_cmp(&ts, &verdict_current->ts) >= 0)  {
                g_print("verdict %" PRIu64 " expired, ignore.\n", verdict_current->id);
                continue;
            };

            timeout = verdict_current->ts.tv_sec - ts.tv_sec;
            if(verdict_current->ts.tv_nsec - ts.tv_nsec > 500000000)
                timeout++;

            if(timeout <= TIMER_MIN)  {
                g_print("verdict %" PRIu64 " expired nearly, ignore.\n", verdict_current->id);;
                continue;
            }
            verdict_current->timer = time(NULL) + timeout;
        }while(0);
        verdict_emit = 1;
        verdict_timer = g_timeout_add(1000, timer_tick, NULL);
        pthread_mutex_unlock(&verdict_lock);

        gdk_threads_enter();
        if(__setup_window(verdict_current))  {
            g_printerr("fail to setup window for verdict id:%" PRIu64 "\n", verdict_current->id);
            gdk_threads_leave();
            continue;
        }
        __set_label(timeout);
        gtk_widget_grab_focus(GTK_WIDGET(gtk_builder_get_object(verdict_builder, "allow_always")));
        gtk_widget_show_all(verdict_win);
        gdk_threads_leave();
    }
    return NULL;
}

static inline void emit_verdict(int verd)
{
    pthread_mutex_lock(&verdict_lock);
    if(verdict_cb)
        verdict_cb(verdict_current->id, verd, verdict_cb_ud);
    verdict_emit = 0;
    if(verdict_timer)  {
        g_source_remove(verdict_timer);
        verdict_timer = 0;
    }
    pthread_cond_broadcast(&verdict_cond);
    pthread_mutex_unlock(&verdict_lock);
}

static void window_close(GtkWidget *widget, gpointer data)
{
    gtk_widget_hide_all(widget);
    emit_verdict(VERDICT_NONE);
}

static int __gtk_window_init(const char *ui)
{
    GtkBuilder *builder = verdict_builder;
    GtkWidget *window = verdict_win;

    if(! window)  {
        if(! (builder = gtk_builder_new()))
            return -1;

        if(! gtk_builder_add_from_file(builder, ui, NULL))  {
            g_object_unref(G_OBJECT(builder));
            return -1;
        }

        gtk_builder_connect_signals(builder, NULL);
        window = GTK_WIDGET(gtk_builder_get_object(builder, "window"));
        always_toggle = GTK_WIDGET(gtk_builder_get_object(builder, "always"));

        if(! window)  {
            g_object_unref(G_OBJECT(builder));
            return -1;
        }

        gtk_window_set_keep_above(GTK_WINDOW(window), TRUE);
        gtk_window_set_urgency_hint(GTK_WINDOW(window), TRUE);
        gtk_window_stick(GTK_WINDOW(window));
        g_signal_connect(window, "destroy", G_CALLBACK(window_close),NULL);
        verdict_win = window;
        verdict_builder = builder;
    }
    return 0;
}

int desert_gtk_init(int *argc, char **argv[], const char *ui, on_verdict cb, void *ud)
{
    static int __gtk_initialized = 0;

    if(! __initialized && cb)  {
        if(! __gtk_initialized)  {
            g_thread_init(NULL);
            gdk_threads_init();
            gtk_init(argc, argv);
            __gtk_initialized = 1;
        }

        if(__gtk_window_init(ui))
            return -1;

        if(pthread_create(&verdict_thread, NULL, desert_gtk_thread, NULL))
            return -1;

        verdict_cb = cb;
        verdict_cb_ud = ud;
        __initialized = 1;
        return 0;
    }
    return -1;
}

int desert_gtk_req_verdict(const msg_verdict_req *req)
{
    verdict_req *vreq;
    verdict_obj *vobj, *vobj_prev;
    const msg_fd_owner *fo;
    size_t sz = sizeof(*vreq);

    assert(__initialized);
    if(! req || req->fo_count <= 0)
        return -1;

    msg_fd_owner_for_each(fo, req)  {
        sz += sizeof(verdict_obj) + strlen(fo->exe) + 1;
    }list_end;

    if(! (vreq = (verdict_req *)malloc(sz)))
        return -1;

    vreq->next = NULL;
    vreq->id = req->id;
    vreq->ts = req->ts;
    vobj = &vreq->objs[0];
    msg_fd_owner_for_each(fo, req)  {
        vobj->uid = fo->euid;
        vobj->gid = fo->egid;
        vobj->pid = fo->pid;
        vobj->ppid = fo->ppid;
        vobj->sid = fo->sid;
        vobj->next = vobj->exe + strlen(fo->exe) + 1;
        strcpy(vobj->exe, fo->exe);
        vobj_prev = vobj;
        vobj = (verdict_obj *)vobj->next;
    }list_end;
    vobj_prev->next = NULL;

    pthread_mutex_lock(&verdict_lock);
    *verdict_list_end = vreq;
    verdict_list_end = &vreq->next;
    pthread_cond_broadcast(&verdict_cond);
    pthread_mutex_unlock(&verdict_lock);
    return 0;
}

void on_allow_clicked(GtkButton *btn, gpointer ud)
{
    int always = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(always_toggle));

    gtk_widget_hide_all(verdict_win);
    emit_verdict(always ? VERDICT_ALLOW_ALWAYS : VERDICT_ALLOW_ONCE);
}

void on_deny_clicked(GtkButton *btn, gpointer ud)
{
    int always = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(always_toggle));

    gtk_widget_hide_all(verdict_win);
    emit_verdict(always ? VERDICT_DENY_ALWAYS : VERDICT_DENY_ONCE);
}

void on_kill_clicked(GtkButton *btn, gpointer ud)
{
    int always = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(always_toggle));

    gtk_widget_hide_all(verdict_win);
    emit_verdict(always ? VERDICT_KILL_ALWAYS : VERDICT_KILL_ONCE);
}

void on_dismiss_clicked(GtkButton *btn, gpointer ud)
{
    gtk_widget_hide_all(verdict_win);
    emit_verdict(VERDICT_NONE);
}

#ifdef TEST_DESERT_GTK
static void do_verdict_cb(uint64_t id, int verd, void *ud)
{
    g_print("verdict %d\n", verd);
}

int main(int argc,char *argv[])
{
    char _req[100];
    msg_verdict_req *req = (msg_verdict_req *)&_req;
    msg_fd_owner *fo = &req->fos[0];

    req->id = 1;
    req->timeout = 10000;
    req->fo_count = 2;
    fo->euid = 10;
    fo->egid = 11;
    fo->pid = 12;
    fo->ppid = 13;
    fo->sid = 14;
    strcpy(fo->exe, "/bin/program1");

    fo = (msg_fd_owner *)(fo->exe + strlen(fo->exe) + 1);
    fo->euid = 20;
    fo->egid = 21;
    fo->pid = 22;
    fo->ppid = 23;
    fo->sid = 24;
    strcpy(fo->exe, "/bin/program2");

    desert_gtk_init(&argc, &argv, "./res/win_verd.ui", do_verdict_cb, NULL);
    desert_gtk_req_verdict(req);
    gtk_main();
    return 0;
}
#endif

