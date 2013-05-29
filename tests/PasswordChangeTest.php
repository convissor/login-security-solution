<?php

/**
 * Test the behaviors when passwords are changed
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
 * Test the behaviors when passwords are changed
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class PasswordChangeTest extends TestCase {
	protected static $pass_1;
	protected static $pass_2;
	protected static $hash_1;
	protected static $hash_2;


	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();

		if (extension_loaded('mbstring')) {
			self::$pass_1 = self::USER_PASS;
		} else {
			self::$pass_1 = 'Some ASCII Only PW 4 You!';
		}
		self::$pass_2 = '!AJd81aasjk2@';
		self::$hash_1 = wp_hash_password(self::$pass_1);
		self::$hash_2 = wp_hash_password(self::$pass_2);
	}

	public function setUp() {
		parent::setUp();

		$options = self::$lss->options;
		$options['pw_change_days'] = 10;
		$options['pw_length'] = 8;
		$options['pw_reuse_count'] = 3;
		self::$lss->options = $options;

		if (!extension_loaded('mbstring')) {
			$this->user->user_pass = self::$pass_1;
		}

		self::$lss->set_pw_force_change($this->user->ID);
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertTrue($actual, 'Problem setting up force change.');

		self::$lss->set_pw_grace_period($this->user->ID);
		$actual = self::$lss->get_pw_grace_period($this->user->ID);
		$this->assertGreaterThan(0, $actual, 'Problem setting up grace period.');
	}


	protected function ensure_grace_and_force_are_empty() {
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual, 'Force change should be false.');

		$actual = self::$lss->get_pw_grace_period($this->user->ID);
		$this->assertSame(0, $actual, 'Grace period should be 0.');
	}

	protected function ensure_grace_and_force_are_populated() {
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertTrue($actual, 'Force change should not be cleared.');

		$actual = self::$lss->get_pw_grace_period($this->user->ID);
		$this->assertGreaterThan(0, $actual, 'Grace period should not be cleared.');
	}

	protected function err($message) {
		return self::$lss->err($message);
	}


	/*
	 * HASHES / REUSED
	 */

	public function test_get_pw_hashes__empty() {
		global $wpdb;

		$wpdb->query('SAVEPOINT empty');

		$actual = self::$lss->get_pw_hashes($this->user->ID);
		$this->assertSame(array(), $actual);
	}

	public function test_save_pw_hash__non_array_edge_case() {
		update_user_meta($this->user->ID, self::$lss->umk_hashes, 'foo');

		$actual = self::$lss->get_pw_hashes($this->user->ID);
		$this->assertEquals(array('foo'), $actual);

		delete_user_meta($this->user->ID, self::$lss->umk_hashes);
	}

	public function test_is_pw_reused__no_reuse_count() {
		$options = self::$lss->options;
		$options['pw_reuse_count'] = 0;
		self::$lss->options = $options;

		$actual = self::$lss->is_pw_reused('abc', $this->user->ID);
		$this->assertNull($actual);
	}

	public function test_is_pw_reused__empty() {
		$actual = self::$lss->is_pw_reused('abc', $this->user->ID);
		$this->assertSame(0, $actual);
	}

	public function test_save_pw_hash__new() {
		$actual = self::$lss->save_pw_hash($this->user->ID, self::$hash_1);
		$this->assertTrue($actual);
	}

	public function test_save_pw_hash__exists() {
		$actual = self::$lss->save_pw_hash($this->user->ID, self::$hash_1);
		$this->assertSame(1, $actual);
	}

	public function test_get_pw_hashes__onehash() {
		$actual = self::$lss->get_pw_hashes($this->user->ID);
		$this->assertEquals(array(self::$hash_1), $actual);
	}

	public function test_is_pw_reused__yes() {
		$actual = self::$lss->is_pw_reused(self::$pass_1, $this->user->ID);
		$this->assertTrue($actual);
	}

	public function test_is_pw_reused__no() {
		$actual = self::$lss->is_pw_reused(self::$pass_2, $this->user->ID);
		$this->assertFalse($actual);
	}

	public function test_save_pw_hash__overflow() {
		global $wpdb;

		self::$lss->save_pw_hash($this->user->ID, 'new1');
		self::$lss->save_pw_hash($this->user->ID, 'new2');
		self::$lss->save_pw_hash($this->user->ID, 'new3');

		$expected = array('new1', 'new2', 'new3');
		$actual = self::$lss->get_pw_hashes($this->user->ID);
		$this->assertEquals($expected, $actual);

		$wpdb->query('ROLLBACK TO empty');
	}

	/*
	 * RESET
	 */

	public function test_password_reset__nullid() {
		$this->user->ID = null;
		$actual = self::$lss->password_reset($this->user, self::$pass_2);
		$this->assertFalse($actual);
	}

	public function test_password_reset__options_0() {
		$options = self::$lss->options;
		$options['pw_change_days'] = 0;  // Don't set change time.
		$options['pw_reuse_count'] = 0;  // Don't save hashes.
		self::$lss->options = $options;

		// Do the deed.
		$actual = self::$lss->password_reset($this->user, self::$pass_1);
		$this->assertNull($actual, 'password_reset() should return null.');

		// Check the outcome...
		$actual = self::$lss->get_pw_changed_time($this->user->ID);
		$this->assertSame(0, $actual, 'Changed time should be 0.');

		$actual = self::$lss->get_pw_hashes($this->user->ID);
		$this->assertSame(array(), $actual, 'Hashes should be empty.');

		$this->ensure_grace_and_force_are_empty();
	}

	public function test_password_reset__normal() {
		global $wpdb;

		$actual = self::$lss->password_reset($this->user, self::$pass_1);
		$this->assertNull($actual, 'password_reset() should return null.');

		// Check the outcome.
		$actual = self::$lss->get_pw_changed_time($this->user->ID);
		$this->assertGreaterThan(0, $actual, 'Changed time should be > 0.');

		$this->ensure_grace_and_force_are_empty();
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_password_reset__reused_pw() {
		global $wpdb;

		$_GET['key'] = 'jk';
		$_GET['login'] = 'ab';

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=rp&key=jk&login=ab&'
				. self::$lss->key_login_msg
				. '=pw-reused';

		$actual = self::$lss->password_reset($this->user, self::$pass_1);
		$this->assertEquals(-2, $actual, 'password_reset() return.');

		$wpdb->query('ROLLBACK TO empty');

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');
	}

	public function test_password_reset__bad_pw() {
		global $wpdb;

		$bad_pw = 'too simple';
		$_GET['key'] = 'jk';
		$_GET['login'] = 'ab';

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=rp&key=jk&login=ab&'
				. self::$lss->key_login_msg
				. '=pw-number';

		$actual = self::$lss->password_reset($this->user, $bad_pw);
		$this->assertEquals(-1, $actual, 'password_reset() return.');

		// Check the outcome.
		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertTrue($actual, 'Force change should not be cleared.');

		$wpdb->query('ROLLBACK TO empty');

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');
	}

	/*
	 * PROFILE UPDATE
	 */

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__no_pass() {
		$errors = new WP_Error;
		$this->user->user_pass = null;
		$actual = self::$lss->user_profile_update_errors($errors, 1, $this->user);
		$this->assertNull($actual);
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__update_no_id() {
		$this->user->ID = null;

		$errors = new WP_Error;
		$actual = self::$lss->user_profile_update_errors($errors, 1, $this->user);
		$this->assertNull($actual);
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__reused() {
		global $wpdb;
		self::$lss->save_pw_hash($this->user->ID, self::$hash_1);

		$errors = new WP_Error;
		$actual = self::$lss->user_profile_update_errors($errors, 1, $this->user);
		$this->assertFalse($actual, 'Bad return value.');
		$this->assertEquals(
			$this->err(__("Passwords can not be reused.", self::ID)),
			$errors->get_error_message()
		);

		$wpdb->query('ROLLBACK TO empty');
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__add_reused_okay() {
		global $wpdb;
		self::$lss->save_pw_hash($this->user->ID, self::$hash_1);

		$errors = new WP_Error;
		$actual = self::$lss->user_profile_update_errors($errors, 0, $this->user);
		$this->assertTrue($actual, 'Bad return value.');

		$this->ensure_grace_and_force_are_empty();

		$wpdb->query('ROLLBACK TO empty');
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__short() {
		$this->user->user_pass = 'aA1!';

		$errors = new WP_Error;
		$actual = self::$lss->user_profile_update_errors($errors, 0, $this->user);
		$this->assertFalse($actual, 'Bad return value.');
		$this->assertEquals(
			$this->err(__("Password is too short.", self::ID)),
			$errors->get_error_message()
		);

		$this->ensure_grace_and_force_are_populated();
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__add() {
		$tmp_id = $this->user->ID;
		$this->user->ID = null;

		$errors = new WP_Error;
		$actual = self::$lss->user_profile_update_errors($errors, 0, $this->user);
		$this->assertTrue($actual, 'Bad return value.');

		$this->user->ID = $tmp_id;
		$this->ensure_grace_and_force_are_populated();
	}
}
