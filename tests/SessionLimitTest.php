<?php

/**
 * Get the class we will use for testing
 */
require_once dirname(__FILE__) .  '/TestCase.php';

/**
 * Test the session limit functionality
 *
 * @package login-security-solution
 * @author
 * @copyright
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class SessionLimitTest extends TestCase {
	protected static $user_ID;

	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}

	public function test_delete_user_session__user_name() {
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

		$options = self::$lss->options;
		$options['session_limit'] = 1;
		self::$lss->options = $options;

		$actual = self::$lss->update_user_session(self::$user_ID);
		$this->assertInternalType('integer', $actual, 'Set last active...');

		$user_ID = null;
		$user_name = $this->user->user_login;
		$actual = self::$lss->delete_user_session($this->user->ID, self::$lss->user_session_id);
		$this->assertInternalType('integer', $actual, 'Delete last active...');
	}

	/*
	 * IS SESSION INVALID
	 */

	public function test_is_session_limit__off() {
		$options = self::$lss->options;
		$options['session_limit'] = 0;
		self::$lss->options = $options;

		$actual = self::$lss->is_session_invalid($this->user->ID);
		$this->assertNull($actual);
	}

	/*
	 * CHECK
	 */

	/**
	 * @depends test_delete_user_session__user_name
	 */
	public function test_check__empty_user_id() {
		$this->user->ID = null;
		$actual = self::$lss->check(array(), $this->user);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_delete_user_session__user_name
	 */
	public function test_check__empty() {
		$actual = self::$lss->check(array(), null);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_delete_user_session__user_name
	 */
	public function test_check__non_user() {
		$other = new stdClass;
		$actual = self::$lss->check(array(), $other);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_delete_user_session__user_name
	 */
	public function test_check__okay() {
		$options = self::$lss->options;
		$options['session_limit'] = 1;
		self::$lss->options = $options;

		$actual = self::$lss->update_user_session($this->user->ID);
		$this->assertTrue($actual, 'Set last active...');

		$actual = self::$lss->check(array(), $this->user);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_check__okay
	 */
	public function test_check__fail() {
		$options = self::$lss->options;
		$options['session_limit'] = 1;
		self::$lss->options = $options;

		$actual = self::$lss->update_user_session($this->user->ID);
		$this->assertTrue($actual, 'Set last active...');

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?redirect_to=%2Fsome%2Fpage&action=login&'
				. self::$lss->key_login_msg . '=session_limit';

		self::$lss->user_session_id='ABCDEFGHIJK0';
		$actual = self::$lss->check(array(), $this->user);

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');

		$this->assertSame(-6, $actual, 'Bad return value.');
	}


}
