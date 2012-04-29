<?php

/**
 * Test the idle timeout functionality
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
 * Test the idle timeout functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class IdleTest extends TestCase {
	protected static $user_ID;


	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}


	public function test_get_last_active__empty_1() {
		$actual = self::$lss->get_last_active($this->user->ID);
		$this->assertSame(0, $actual);
	}

	public function test_set_last_active__add() {
		$actual = self::$lss->set_last_active($this->user->ID);
		$this->assertInternalType('integer', $actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_last_active__add
	 */
	public function test_set_last_active__update() {
		sleep(1);
		$actual = self::$lss->set_last_active($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_last_active__update
	 */
	public function test_get_last_active__something() {
		$actual = self::$lss->get_last_active($this->user->ID);
		$diff = (time() - $actual) < 1;
		$this->assertGreaterThanOrEqual(0,  $diff, 'Time was too long ago.');
		$this->assertLessThanOrEqual(1, $diff, 'Time was in the future.');
	}

	/**
	 * @depends test_get_last_active__something
	 */
	public function test_delete_last_active__1() {
		global $user_ID;
		$user_ID = $this->user->ID;
		$actual = self::$lss->delete_last_active();
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_delete_last_active__1
	 */
	public function test_get_last_active__empty_2() {
		$actual = self::$lss->get_last_active($this->user->ID);
		$this->assertSame(0, $actual);
	}

	public function test_delete_last_active__null_both() {
		global $user_ID, $user_name;
		$user_ID = null;
		$user_name = null;
		$actual = self::$lss->delete_last_active();
		$this->assertNull($actual, 'Bad return value.');
	}

	public function test_delete_last_active__user_name() {
		global $user_ID, $user_name, $wpdb;

		$actual = $wpdb->insert(
			$wpdb->users,
			array(
				'user_login' => $this->user->user_login,
			)
		);
		$this->assertSame(1, $actual, 'Could not insert sample record.');

		// Save this for later use.
		self::$user_ID = $wpdb->insert_id;

		$actual = self::$lss->set_last_active(self::$user_ID);
		$this->assertInternalType('integer', $actual, 'Set last active...');

		$user_ID = null;
		$user_name = $this->user->user_login;
		$actual = self::$lss->delete_last_active();
		$this->assertTrue($actual, 'Delete last active...');
	}

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_delete_last_active__user_name_unknown() {
		global $user_ID, $user_name;

		$actual = self::$lss->set_last_active(self::$user_ID);
		$this->assertInternalType('integer', $actual, 'Set last active...');

		$user_ID = null;
		$user_name = 'nowaycanthisnameexistokayprettyplease';
		$actual = self::$lss->delete_last_active();
		$this->assertEquals(-1, $actual, 'Delete last active...');
	}

	/*
	 * AUTH COOKIE EXPIRED
	 */

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_auth_cooke_expired__user_name_unknown() {
		$cookie_elements = array(
			'username' => 'nowaycanthisnameexistokayprettyplease',
		);
		$actual = self::$lss->auth_cookie_expired($cookie_elements);
		$this->assertEquals(-1, $actual, 'auth_cookie_expired');
	}

	/**
	 * @depends test_delete_last_active__user_name_unknown
	 */
	public function test_auth_cookie_expired__normal() {
		global $user_ID, $user_name, $wpdb;

		$actual = self::$lss->get_last_active(self::$user_ID);
		$this->assertInternalType('integer', $actual, 'get_last_active');
		$this->assertGreaterThan(0, $actual, 'get_last_active');

		$cookie_elements = array(
			'username' => $this->user->user_login,
		);
		$actual = self::$lss->auth_cookie_expired($cookie_elements);
		$this->assertTrue($actual, 'auth_cookie_expired');

		$actual = self::$lss->get_last_active(self::$user_ID);
		$this->assertSame(0, $actual, 'get_last_active');
	}

	public function test_auth_cooke_expired__user_name_empty() {
		$cookie_elements = array();
		$actual = self::$lss->auth_cookie_expired($cookie_elements);
		$this->assertNull($actual, 'auth_cookie_expired');
	}

	/*
	 * IS IDLE
	 */

	public function test_is_idle__off() {
		$options = self::$lss->options;
		$options['idle_timeout'] = 0;
		self::$lss->options = $options;

		$actual = self::$lss->is_idle($this->user->ID);
		$this->assertNull($actual);
	}

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_is_idle__add() {
		$options = self::$lss->options;
		$options['idle_timeout'] = 15;
		self::$lss->options = $options;

		$actual = self::$lss->is_idle($this->user->ID);
		$this->assertSame(0, $actual, 'Bad return value.');

		$actual = self::$lss->get_last_active($this->user->ID);
		$diff = (time() - $actual) < 1;
		$this->assertGreaterThanOrEqual(0,  $diff, 'Time was too long ago.');
		$this->assertLessThanOrEqual(1, $diff, 'Time was in the future.');
	}

	/**
	 * @depends test_is_idle__add
	 */
	public function test_is_idle__update() {
		$options = self::$lss->options;
		$options['idle_timeout'] = 1;
		self::$lss->options = $options;

		$actual = self::$lss->is_idle($this->user->ID);
		$this->assertFalse($actual);
	}

	/**
	 * @depends test_is_idle__update
	 */
	public function test_is_idle__true() {
		$options = self::$lss->options;
		$options['idle_timeout'] = -1;
		self::$lss->options = $options;

		$actual = self::$lss->is_idle($this->user->ID);
		$this->assertTrue($actual);
	}

	/*
	 * CHECK
	 */

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_check__empty_user_id() {
		$this->user->ID = null;
		$actual = self::$lss->check(array(), $this->user);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_check__empty() {
		$actual = self::$lss->check(array(), null);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_check__non_user() {
		$other = new stdClass;
		$actual = self::$lss->check(array(), $other);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_delete_last_active__user_name
	 */
	public function test_check__okay() {
		$options = self::$lss->options;
		$options['idle_timeout'] = 1;
		self::$lss->options = $options;

		$actual = self::$lss->check(array(), $this->user);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_check__okay
	 */
	public function test_check__fail() {
		$options = self::$lss->options;
		$options['idle_timeout'] = -1;
		self::$lss->options = $options;

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=login&'
				. self::$lss->key_login_msg . '=idle';

		$actual = self::$lss->check(array(), $this->user);

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');

		$this->assertSame(-5, $actual, 'Bad return value.');
	}
}
