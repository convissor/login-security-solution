<?php

/**
 * Test the disable login functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */

/**
 * Get the class we will use for testing
 */
require_once dirname(__FILE__) .  '/TestCase.php';

/**
 * Test the disable login functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class DisableLoginTest extends TestCase {
	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}


	public function test_disable_login__false() {
		$options = self::$lss->options;
		$options['disable_logins'] = 0;
		self::$lss->options = $options;

		$actual = self::$lss->check(array(), $this->user);
		$this->assertTrue($actual, 'Bad return value.');
	}

	public function test_disable_login__true() {
		$options = self::$lss->options;
		$options['disable_logins'] = 1;
		self::$lss->options = $options;

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=login';

		$actual = self::$lss->check(array(), $this->user);

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');

		$this->assertSame(-4, $actual, 'Bad return value.');
	}

	public function test_disable_login__true_but_admin() {
		global $current_user;

		$options = self::$lss->options;
		$options['disable_logins'] = 1;
		self::$lss->options = $options;

		wp_set_current_user(1);

		$actual = self::$lss->check(array(), $this->user);
		$this->assertTrue($actual, 'Bad return value.');
	}
}
