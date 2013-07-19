/*
 * lavender-gtk.c The GTK front end of Lavender.
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <libnotify/notify.h>

#include "config.h"
#include "desert.h"
#include "desert_gtk.h"

#ifndef CONFIG_STAT_DIR
#define CONFIG_STAT_DIR "/var/run/"
#endif

#ifndef CONFIG_STAT_FILE
#define CONFIG_STAT_FILE PACKAGE_NAME ".stat"
#endif

#define CONFIG_STAT_PATH (CONFIG_STAT_DIR CONFIG_STAT_FILE)

enum{
    MENU_TOGGLE_CONNECT,
    MENU_TOGGLE_CACTUS,
    MENU_QUIT,
    MENU_SEPARATOR,
    MENU_ABOUT,

    NUM_MENU,
};

static const char banner[] = "Lavender GTK+ Front-End";
static const char *lavender_icon[3] = {
    ICON_OFFLINE,
    ICON_DISABLED,
    ICON_ONLINE,
};

/* protected under gdk thread safe lock */
static int registered = 0;
static int cactus_status = CACTUS_INACTIVE;

static GtkStatusIcon *status_icon = NULL;
static NotifyNotification *status_noti = NULL;
static GtkWidget *popup_menu = NULL;
static GtkWidget *menu_item[NUM_MENU] = {
    [0 ... NUM_MENU - 1] = NULL,
};

static void quick_msg(const char *msg, int type)
{
    GtkWidget *dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                type, GTK_BUTTONS_CLOSE, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void notify_msg(const char *sum, const char *body, const char *icon)
{
    NotifyNotification *noti = status_noti;

    if(! noti)  {
        noti = notify_notification_new_with_status_icon(sum, body, icon, status_icon);
        status_noti = noti;
    }else  {
        notify_notification_update(noti, sum, body, icon);
    }
    notify_notification_set_timeout(noti, 5000);
    notify_notification_show(noti, NULL);
}

static void on_connect_cb(int state, unsigned int peer, void *ud)
{
    gdk_threads_enter();
    if(! state)  {
        g_printerr("passively disconnected from Cactus Runtime\n");
        desert_disconnect();
        registered = 0;
        if(status_icon)  {
            gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CONNECT]), "Connect");
            gtk_widget_set_sensitive(menu_item[MENU_TOGGLE_CACTUS], FALSE);
            gtk_status_icon_set_from_file(status_icon, lavender_icon[registered]);
        }
        notify_msg("Lavender service unavailable, disconnected", NULL, ICON_ONLINE);
    }
    gdk_threads_leave();
}

static void on_verdict_cb(int type, const void *msg, void *ud)
{
    switch(type)  {
    case CACTUS_VERDICT_REQUEST:  {
        desert_gtk_req_verdict((const msg_verdict_req *)msg);
        break;
    }
    case CACTUS_RUNTIME_INFO:  {
        const msg_runtime_info *info = (const msg_runtime_info *)msg;

        switch(info->type)  {
        case INFO_MSG:
            gdk_threads_enter();
            notify_msg(info->info, NULL, ICON_ONLINE);
            gdk_threads_leave();
            break;
        default:
            g_print("unrecognized verdict info:%d",  info->type);
            break;
        }
        break;
    }
    default:  {
        g_print("unrecognized verdict message:%d", type);
        break;
    }
    }
}

static void on_toggle_connection(GtkMenuItem *item, gpointer data)
{
    if(! registered)  {
        if(desert_connect(NULL, NULL, 0))  {
            quick_msg("Failed to init connection to Lavender!", GTK_MESSAGE_ERROR);
            return;
        }
        if(desert_register_fe(0, on_verdict_cb, NULL))  {
            quick_msg("Failed to self register!", GTK_MESSAGE_ERROR);
            return;
        }
        registered = 1;
        gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CONNECT]), "Disconnect");
        cactus_status = desert_cactus_status();
        gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CACTUS]),
                                cactus_status == CACTUS_ACTIVE ? "Disable" : "Enable");
        if(cactus_status == CACTUS_ACTIVE)
            registered++;
        gtk_widget_set_sensitive(menu_item[MENU_TOGGLE_CACTUS], TRUE);
        gtk_status_icon_set_from_file(status_icon, lavender_icon[registered]);
    }else  {
        desert_disconnect();
        registered = 0;
        cactus_status = -1;
        gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CONNECT]), "Connect");
        gtk_widget_set_sensitive(menu_item[MENU_TOGGLE_CACTUS], FALSE);
        gtk_status_icon_set_from_file(status_icon, lavender_icon[registered]);
    }
}

static void on_toggle_cactus(GtkMenuItem *item, gpointer data)
{
    if(registered)  {
        if(cactus_status == CACTUS_ACTIVE)  {
            if(desert_switch_cactus(0))  {
                quick_msg("Fail to disable the Lavender!", GTK_MESSAGE_ERROR);
                return;
            }
        }else  {
            if(desert_switch_cactus(1))  {
                quick_msg("Fail to enable the Lavender!", GTK_MESSAGE_ERROR);
                return;
            }
        }
        registered = 1;
        cactus_status = desert_cactus_status();
        gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CACTUS]),
                                cactus_status == CACTUS_ACTIVE ? "Disable" : "Enable");
        if(cactus_status == CACTUS_ACTIVE)
            registered++;
        gtk_status_icon_set_from_file(status_icon, lavender_icon[registered]);
    }
}

static void on_quit(GtkMenuItem *item, gpointer data)
{
    gtk_main_quit();
}

static void on_about(GtkMenuItem *item, gpointer data)
{
    static const char *artists[] = {
        "Crs Chin <crs.chin@gmail.com>",
        NULL,
    };

    gtk_show_about_dialog(NULL,
                          "program-name", banner,
                          "title", PACKAGE_NAME,
                          "comments", "Light weight personal firewall, auditing applications network access and behavior.",
                          "authors", artists,
                          "version", VERSION,
                          "logo", gdk_pixbuf_new_from_file_at_size(lavender_icon[2], 64, 64, NULL),
                          NULL);
}

static void on_popup_menu(GtkStatusIcon *icon, guint button, guint activate_time, gpointer data)
{
    gtk_widget_show_all(popup_menu);
    gtk_menu_popup(GTK_MENU(popup_menu), NULL, NULL, NULL, NULL, button, activate_time);
}

static void on_verdict_res(uint64_t id, int verdict, void *ud)
{
    desert_send_verdict(id, verdict);
}

static GtkWidget *__init_menu(void)
{
    GtkWidget *menu = gtk_menu_new();
    GtkWidget *item;

    item = gtk_menu_item_new_with_label(registered ? "Disconnect" : "Connect");
    g_signal_connect(item, "activate", G_CALLBACK(on_toggle_connection), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    menu_item[MENU_TOGGLE_CONNECT] = item;

    item = gtk_menu_item_new_with_label(cactus_status == CACTUS_ACTIVE ? "Disable" : "Enable");
    g_signal_connect(item, "activate", G_CALLBACK(on_toggle_cactus), NULL);
    gtk_widget_set_sensitive(item, registered ? TRUE : FALSE);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    menu_item[MENU_TOGGLE_CACTUS] = item;

    item = gtk_image_menu_item_new_from_stock(GTK_STOCK_QUIT, NULL);
    g_signal_connect(item, "activate", G_CALLBACK(on_quit), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    menu_item[MENU_QUIT] = item;

    item = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    menu_item[MENU_SEPARATOR] = item;

    item = gtk_image_menu_item_new_from_stock(GTK_STOCK_ABOUT, NULL);
    g_signal_connect(item, "activate", G_CALLBACK(on_about), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    menu_item[MENU_ABOUT] = item;

    return menu;
}

static ssize_t file_read(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY);
    ssize_t ret = -1;

    if(fd >= 0)  {
        ret = read(fd, buf, sz);
        close(fd);
    }
    return ret;
}

static void on_service_stat_changed(GFileMonitor *m,
                                    GFile *f,
                                    GFile *of,
                                    GFileMonitorEvent event,
                                    gpointer ud)
{
    char buf[50];
    ssize_t len;

    if(event == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT
       && ! strcmp(g_file_get_path(f), CONFIG_STAT_PATH))  {
        len = file_read(CONFIG_STAT_PATH, buf, sizeof(buf) - 1);
        if(len > 0)  {
            buf[len] = '\0';
            g_print("lavender service state:\"%s\"\n", buf);
            if(! strcmp(buf, "AVAILABLE"))  {
                g_print("lavender service available now, try connect ...\n");
                gdk_threads_enter();
                if(desert_connect(NULL, NULL, 0))  {
                    g_printerr("Failed to init connection to Lavender!\n");
                    goto out;
                }
                if(desert_register_fe(0, on_verdict_cb, NULL))  {
                    g_printerr("Failed to self register!\n");
                    goto out;
                }
                registered = 1;
                gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CONNECT]), "Disconnect");
                cactus_status = desert_cactus_status();
                gtk_menu_item_set_label(GTK_MENU_ITEM(menu_item[MENU_TOGGLE_CACTUS]),
                                        cactus_status == CACTUS_ACTIVE ? "Disable" : "Enable");
                if(cactus_status == CACTUS_ACTIVE)
                    registered++;
                gtk_widget_set_sensitive(menu_item[MENU_TOGGLE_CACTUS], TRUE);
                gtk_status_icon_set_from_file(status_icon, lavender_icon[registered]);
                notify_msg("Lavender service available, connected", NULL, ICON_ONLINE);
            out:
                gdk_threads_leave();
            }
        }
    }
}

static void init_monitor(void)
{
    GFile *f = g_file_new_for_path(CONFIG_STAT_DIR);
    GFileMonitor *m = g_file_monitor_directory(f, G_FILE_MONITOR_NONE, NULL, NULL);

    if(! m)  {
        g_printerr("unable to monitor dir \"%s\", stop\n", CONFIG_STAT_DIR);
        g_object_unref(f);
        return;
    }

    g_signal_connect(m, "changed", G_CALLBACK(on_service_stat_changed), NULL);
}

static int pid_lock(const char *dir)
{
    static int lock_fd = -1;
    char file[PATH_MAX];
    pid_t pid = getpid();
    struct flock lock;
    char s_pid[20];
    int fd, len;
    mode_t mode;

    if(lock_fd >= 0)  {
        g_printerr("pid lock held already\n");
        return -1;
    }

    snprintf(file, sizeof(file), "%s/lavender-gtk.pid", dir);
    mode = umask(S_IRGRP | S_IROTH);
    fd = open(file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    /* restore incase different */
    umask(mode);
    if(fd < 0)  {
        g_printerr("Error open pid lock file:%d(%s)\n", errno, strerror(errno));
        return -1;
    }

    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    len = sprintf(s_pid, "%u\n", pid);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if(! fcntl(fd, F_SETLK, &lock)
       && ! ftruncate(fd, 0)
       && write(fd, s_pid, len) == len)  {
        lock_fd = fd;
        return 0;
    }
    close(fd);
    return -1;
}

int main(int argc, char *argv[])
{
    GtkStatusIcon *status;
    int err;

    if(pid_lock(g_get_user_data_dir()))  {
        g_printerr("unable to init pid lock, another instance running?\n");
        return -1;
    }

    if((err = desert_init(banner, on_connect_cb, NULL)))  {
        g_printerr("fail to init desert!\n");
        return -1;
    }

    if(desert_gtk_init(&argc, &argv, LAVENDER_GTK_UI, on_verdict_res, NULL))  {
        g_printerr("fail to init desert GTK!\n");
        return -1;
    }

    if((err = desert_connect(NULL, NULL, 0)))
        g_printerr("fail to init connection to Lavender.\n");

    if(! err)  {
        if((err = desert_register_fe(0, on_verdict_cb, NULL)))
            g_printerr("fail to self-register as front-end\n");
    }

    if(! err)  {
        registered = 1;
        cactus_status = desert_cactus_status();
        if(cactus_status == CACTUS_ACTIVE)
            registered++;
    }

    init_monitor();

    gdk_threads_enter();

    status = gtk_status_icon_new_from_file(lavender_icon[registered]);

    popup_menu = __init_menu();

    g_object_set(status, "tooltip-text", "Lavender, the GTK+ Console", NULL);
    g_signal_connect(status, "popup-menu", G_CALLBACK(on_popup_menu), NULL);
    status_icon = status;
    gdk_threads_leave();

    gtk_main();
    return 0;
}
