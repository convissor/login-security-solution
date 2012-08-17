#! /bin/bash -e

cd "`dirname "$0"`"

while read file ; do
	echo "Merging $file..."
	msgmerge -vUN --backup=off $file login-security-solution.pot
done < <(ls *po)
