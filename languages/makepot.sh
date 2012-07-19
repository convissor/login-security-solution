#! /bin/bash -e

cd "`dirname "$0"`/../../makepot"

svn up

php -d 'error_reporting=E_ALL^E_STRICT' \
	makepot.php wp-plugin \
	../login-security-solution \
	../login-security-solution/languages/login-security-solution.pot
