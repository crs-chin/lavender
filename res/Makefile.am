icon_DATA = Lavender.png Lavender-offline.png Lavender-disabled.png
icondir = $(datadir)/pixmaps

win_verd.ui:win_verd.ui.in
	sed -e "s|\@LAVENDER_ICON\@|$(datadir)/pixmaps/Lavender.png|" $< > $@

lavender-gtk.desktop:lavender-gtk.desktop.in
	sed -e "s|\@LAVENDER_GTK_PATH\@|$(bindir)/lavender-gtk|" \
	-e "s|\@LAVENDER_ICON\@|$(datadir)/pixmaps/Lavender.png|" $< > $@

desktop_DATA = lavender-gtk.desktop
desktopdir = $(datadir)/applications

ui_DATA = win_verd.ui
uidir = $(datadir)/lavender/

CLEANFILES = $(ui_DATA) $(desktop_DATA)
EXTRA_DIST = Lavender.png Lavender-offline.png Lavender-disabled.png  \
			win_verd.ui.in \
			lavender-gtk.desktop.in


