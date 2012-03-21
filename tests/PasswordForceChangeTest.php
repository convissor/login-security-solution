<?php

/**
 * Test the force password change functionality
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
 * Test the force password change functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class PasswordForceChangeTest extends TestCase {
	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}


	public function test_get_pw_force_change__false_1() {
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual);
	}

	public function test_check__pre_threshold() {
		$actual = self::$lss->check(array(), $this->user);
		$this->assertTrue($actual);
	}

	public function test_set_pw_force_change__add() {
		$actual = self::$lss->set_pw_force_change($this->user->ID);
		$this->assertInternalType('integer', $actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_force_change__add
	 */
	public function test_get_pw_force_change__true() {
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_get_pw_force_change__true
	 */
	public function test_check__post_threshold() {
		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=retrievepassword&'
				. self::$lss->key_login_msg . '=pw_force';

		$actual = self::$lss->check(array(), $this->user);

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');

		$this->assertSame(-3, $actual, 'Bad return value.');
	}

	/**
	 * @depends test_get_pw_force_change__true
	 */
	public function test_delete_pw_force_change() {
		$actual = self::$lss->delete_pw_force_change($this->user->ID);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_delete_pw_force_change
	 */
	public function test_get_pw_force_change__false_2() {
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual);
	}
}
