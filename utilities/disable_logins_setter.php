<?php

/**
 * A script for enabling and disabling the Disable Logins feature of
 * the Login Security Solution WordPress plugin
 *
 * @package login-security-solution
 * @link http://wordpress.org/extend/plugins/login-security-solution/
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 */

$option_name = 'login-security-solution-options';


function usage() {
	echo "Usage:  disable_logins_setter.php <enabled>\n";
	echo "  @param int enabled  should logins be disabled? 1 = yes, 0 = no.\n";
	echo "\nAuthor: Daniel Convissor <danielc@analysisandsolutions.com>\n";
	echo "License: http://www.analysisandsolutions.com/software/license.htm\n";
	echo "Link: http://wordpress.org/extend/plugins/login-security-solution/\n";
	exit(1);
}

if (!isset($_SERVER['argv'][1])) {
	usage();
} else {
	$enabled = $_SERVER['argv'][1];
	if ($enabled !== '0' && $enabled !== '1') {
		usage();
	}
}


/*
 * Uses dirname(__FILE__) because "./" can be stripped by PHP's
 * safety settings and __DIR__ was introduced in PHP 5.3.
 */
$util_dir = realpath(dirname(__FILE__));
$root_dir = "$util_dir/../../../..";

/** Gather WordPress infrastructure */
require_once "$root_dir/wp-load.php";

$option_value = get_option($option_name);
$option_value['disable_logins'] = $enabled;
if (!update_option($option_name, $option_value)) {
	echo "ERROR: updating the option had a problem.\n";
	exit(1);
}
