#! /bin/bash -e

cd "`dirname "$0"`"

while read file ; do
	lang=${file%*.po}
	echo "Building $lang..."
	msgfmt -o $lang.mo $lang.po
done < <(ls *po)
