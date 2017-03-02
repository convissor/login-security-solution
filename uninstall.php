<?php
/**
 * @package login-security-solution
 * @link https://wordpress.org/plugins/login-security-solution/
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012-2014
 */

if (!defined('ABSPATH') && !defined('WP_UNINSTALL_PLUGIN')) {
	exit();
}

delete_site_option('login-security-solution-options');
delete_site_option('login-security-solution-pw-force-change-done');
