AUTOMAKE_OPTIONS = foreign

SUBDIRS = cactus res

sbin_PROGRAMS = lavender
sbin_SCRIPTS = lavender-launch

bin_PROGRAMS = lavender-gtk lotus

do_subst = sed -e "s|\@LAVENDER_PATH\@|$(bindir)/lavender|g"

lavender-launch:lavender-launch.in
	$(do_subst) < $< > $@

lavender_SOURCES = lavender.c
lavender_LDADD = cactus/libcactus.la
lavender_CFLAGS = -Icactus/port

lib_LTLIBRARIES = libdesert.la libdesert_gtk.la
libdesert_la_SOURCES = 	desert.c  \
						desert.h  \
						ipclite.c  \
						ipclite_client.c  \
						ipclite.h  \
						ipclite_priv.h  \
						msg_base.h  \
						rpclite.c  \
						rpclite.h  \
						util.h

libdesert_la_CFLAGS = -O3 -fno-strict-aliasing -Icactus/port

libdesert_gtk_la_SOURCES = 	desert_gtk.c  \
							desert_gtk.h
libdesert_gtk_la_LIBADD = $(GTK_LIBS)
libdesert_gtk_la_CFLAGS = $(GTK_CFLAGS) -O3 -fno-strict-aliasing -Icactus/port

lotus_SOURCES = lotus.c
lotus_LDADD = libdesert.la -lreadline
lotus_CFLAGS = -Icactus/port

lavender_gtk_SOURCES = lavender-gtk.c
lavender_gtk_LDADD = libdesert.la libdesert_gtk.la $(GTK_LIBS) $(NOTIFY_LIBS) $(GIO_LIBS)
lavender_gtk_CFLAGS = $(GTK_CFLAGS) $(NOTIFY_CFLAGS) $(GIO_CFLAGS) -export-dynamic  \
			-DICON_ONLINE=\"$(datadir)/pixmaps/Lavender.png\"  \
			-DICON_OFFLINE=\"$(datadir)/pixmaps/Lavender-offline.png\"  \
			-DICON_DISABLED=\"$(datadir)/pixmaps/Lavender-disabled.png\"	\
			-DLAVENDER_GTK_UI=\"$(datadir)/lavender/win_verd.ui\"	\
			-Icactus/port

extra_DATA = TODO \
			ChangeLog \
			COPYING \
			README

extradir = $(datadir)/info/lavender

CLEANFILES = $(sbin_SCRIPTS)
EXTRA_DIST = cust.h \
			lavender-launch.in \
			javender/README  \
			javender/jni/jni_javender.c \
			javender/README \
			javender/src/com/javender/CactusMsg.java \
			javender/src/com/javender/Javender.java \
			javender/src/com/javender/VerdictReq.java \
			Avender/ic_launcher-web.png \
			Avender/proguard-project.txt \
			Avender/src/com/android/avender/MainActivity.java \
			Avender/src/com/android/avender/VerdictInfo.java \
			Avender/src/com/android/avender/IAvenderService.aidl \
			Avender/src/com/android/avender/AutoStartReceiver.java \
			Avender/src/com/android/avender/VerdictInfo.aidl \
			Avender/src/com/android/avender/VerdictRequest.java \
			Avender/src/com/android/avender/AvenderService.java \
			Avender/project.properties \
			Avender/res/values-v11/styles.xml \
			Avender/res/values-sw600dp/dimens.xml \
			Avender/res/layout/verdict_request.xml \
			Avender/res/layout/activity_main.xml \
			Avender/res/layout/verdict_item.xml \
			Avender/res/drawable-xhdpi/ic_launcher.png \
			Avender/res/values-sw720dp-land/dimens.xml \
			Avender/res/values-v14/styles.xml \
			Avender/res/drawable-hdpi/ic_launcher.png \
			Avender/res/drawable-hdpi/prog.png \
			Avender/res/values/styles.xml \
			Avender/res/values/strings.xml \
			Avender/res/values/dimens.xml \
			Avender/res/drawable-mdpi/ic_launcher.png \
			Avender/res/drawable-xxhdpi/ic_launcher.png \
			Avender/res/menu/main.xml \
			Avender/AndroidManifest.xml \
			Avender/Android.mk

