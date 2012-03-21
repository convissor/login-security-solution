<?php

/**
 * Test speeds of various password tests
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

$user = new stdClass;
$user->user_login = 'aaaa';
$user->user_email = 'bbbb';
$user->user_url = 'cccc';
$user->first_name = 'dddd';
$user->last_name = 'eeee';
$user->nickname = 'ffffffff';
$user->display_name = 'gggggggg';
$user->aim = 'hhhhhhhh';
$user->yim = 'iiiiiiii';
$user->jabber = 'jjjjjjjj';
$user->user_pass = 'aA1!gt%vE8#';

for ($i = 0; $i < 100; $i++) {
	$lss->validate_pw($user);
}
