<?php

/**
 * Shrinks the size of password dictionary files by removing entries
 * that fail our other tests
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */

/**
 * Gather the WordPress infrastructure.
 * Use dirname(dirname()) because safe mode can disable "../".
 */
require_once dirname(dirname(dirname(dirname(dirname(__FILE__))))) . '/wp-load.php';

/**
 * Obtain the plugin class
 */
require_once dirname(dirname(__FILE__)) . '/login-security-solution.php';
$lss = $GLOBALS['login_security_solution'];

$files = array();
$dir = new DirectoryIterator($lss->dir_dictionaries);
foreach ($dir as $file) {
	if ($file->isDir() || $file->getFilename() == 'test.txt') {
		continue;
	}
	$files[$lss->dir_dictionaries . $file->getFilename()]	= $file->getSize();
}

// Sort by size.
asort($files);

// Simplify array.  For future needs.
$file_names = array_keys($files);

foreach ($file_names as $file) {
	$fh_old = fopen($file, 'r');
	$fh_new = fopen("$file.new", 'w');
	while ($line = fgets($fh_old)) {
		if ($lss->validate_pw($line)) {
			$fh_new->fwrite("$line\n");
		}
	}
	fclose($fh_new);
	fclose($fh_old);
	rename("$file.new", $file);
}

// The existing tests knock out all of the dictionary passwords.
// So don't bother completing the code to reduce things further.
exit;

foreach ($file_names as $file) {
	$smaller_file = array_shift($file_names);

	if ($file != $smaller_file) {
		foreach ($file_names as $bigger_file) {
			// grep 
		}
	}
}
