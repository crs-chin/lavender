#!/bin/bash
#
# Copyright (C) <2013>  Crs Chin<crs.chin@gmail.com>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#/

PAYLOAD=""
EXTRACT_COMMAND="tar xzv -C"
INSTALLER_PATH=""
OUTPUT_PATH=""

usage()
{
    echo "$0 [OPTIONS] PAYLOAD"
    echo "OPTIONS:"
    echo "  -c  command to extract payload from input to output"
    echo "  -p  internal installer path in the payload"
    echo "  -o  file to output"
    echo "  -h  show this message"
}

while [ -n "$1" ];
do
    if [ "$1" = "-c" ];then
        shift
        EXTRACT_COMMAND="$1"
    elif [ "$1" = "-p" ];then
        shift
        INSTALLER_PATH="$1"
    elif [ "$1" = "-o" ];then
        shift
        OUTPUT_PATH="$1"
    elif [ "$1" = "-h" ];then
        usage;
    elif [ -z "$PAYLOAD" ];then
        PAYLOAD="$1"
    else
        echo "unrecognized command %1, abort!"
        exit -1;
    fi
    shift
done

error()
{
    echo "$@"
    exit -1
}

if [ -z "$PAYLOAD" ];then
    error "Payload required!"
fi

if [ -z "$INSTALLER_PATH" ];then
    error "Installer needs to be defined!"
fi

if [ -z "$OUTPUT_PATH" ];then
    error "No where to output!"
fi

echo -n "Generating installation package..."

cat > "$OUTPUT_PATH" <<EOF
#!/bin/bash
echo ""
echo "Extracting ..."
echo ""

export TMPDIR=\$(mktemp -d /tmp/selfextract.XXXXXX)

ARCHIVE=\$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' \$0)

tail -n+\$ARCHIVE \$0 | $EXTRACT_COMMAND \$TMPDIR

CDIR=\$(pwd)
cd \$TMPDIR
cd $(dirname "$INSTALLER_PATH")
./$(basename "$INSTALLER_PATH")

cd $CDIR
rm -rf $TMPDIR

exit 0

__ARCHIVE_BELOW__
EOF

cat "$PAYLOAD" >> "$OUTPUT_PATH"
chmod +x "$OUTPUT_PATH"

echo "done"
echo "All ready at \"$OUTPUT_PATH\""

