<?php

/**
 * Test the password expiration functionality
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
 * Test the password expiration functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class PasswordExpirationTest extends TestCase {
	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}

	public function setUp() {
		parent::setUp();

		$options = self::$lss->options;
		$options['pw_change_days'] = 10;
		$options['pw_change_grace_period_minutes'] = 10;
		self::$lss->options = $options;
	}


	/*
	 * CHANGED TIME CRUD
	 */

	public function test_get_pw_changed_time__0() {
		$actual = self::$lss->get_pw_changed_time($this->user->ID);
		$this->assertSame(0, $actual);
	}

	public function test_set_pw_changed_time__add() {
		global $wpdb;
		$wpdb->query('SAVEPOINT no_pw_change_time');

		$actual = self::$lss->set_pw_changed_time($this->user->ID);
		$this->assertInternalType('integer', $actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_changed_time__add
	 */
	public function test_set_pw_changed_time__update() {
		sleep(1);
		$actual = self::$lss->set_pw_changed_time($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_changed_time__update
	 */
	public function test_get_pw_changed_time__something() {
		global $wpdb;

		$actual = self::$lss->get_pw_changed_time($this->user->ID);
		$diff = (time() - $actual) < 1;
		$this->assertGreaterThanOrEqual(0,  $diff, 'Time was too long ago.');
		$this->assertLessThanOrEqual(1, $diff, 'Time was in the future.');

		$wpdb->query('ROLLBACK TO no_pw_change_time');
	}

	/*
	 * GRACE PERIOD CRUD
	 */

	public function test_get_pw_grace_period__0() {
		$actual = self::$lss->get_pw_grace_period($this->user->ID);
		$this->assertSame(0, $actual);
	}

	public function test_set_pw_grace_period__add() {
		$actual = self::$lss->set_pw_grace_period($this->user->ID);
		$this->assertInternalType('integer', $actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_grace_period__add
	 */
	public function test_set_pw_grace_period__update() {
		sleep(1);
		$actual = self::$lss->set_pw_grace_period($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_grace_period__update
	 */
	public function test_get_pw_grace_period__something() {
		$actual = self::$lss->get_pw_grace_period($this->user->ID);
		$diff = (time() - $actual) < 1;
		$this->assertGreaterThanOrEqual(0,  $diff, 'Time was too long ago.');
		$this->assertLessThanOrEqual(1, $diff, 'Time was in the future.');
	}

	/**
	 * @depends test_set_pw_grace_period__add
	 */
	public function test_delete_pw_grace_period() {
		$actual = self::$lss->delete_pw_grace_period($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/*
	 * IS EXPIRED
	 */

	public function test_is_pw_expired__disabled() {
		$options = self::$lss->options;
		$options['pw_change_days'] = 0;
		self::$lss->options = $options;

		$actual = self::$lss->is_pw_expired($this->user->ID);
		$this->assertNull($actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_changed_time__add
	 * @depends test_get_pw_changed_time__something
	 */
	public function test_is_pw_expired__new() {
		$actual = self::$lss->is_pw_expired($this->user->ID);
		$this->assertSame(0, $actual, 'Bad return value.');
	}

	/**
	 * @depends test_is_pw_expired__new
	 */
	public function test_is_pw_expired__not_expired() {
		$actual = self::$lss->is_pw_expired($this->user->ID);
		$this->assertFalse($actual, 'Bad return value.');
	}

	/**
	 * @depends test_is_pw_expired__new
	 */
	public function test_is_pw_expired__expired() {
		$options = self::$lss->options;
		$options['pw_change_days'] = -1;
		self::$lss->options = $options;

		$actual = self::$lss->is_pw_expired($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/*
	 * CHECK GRACE PERIOD
	 */

	/**
	 * @depends test_delete_pw_grace_period
	 */
	public function test_check_pw_grace_period__unset() {
		$actual = self::$lss->check_pw_grace_period($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_check_pw_grace_period__unset
	 */
	public function test_check_pw_grace_period__in_effect() {
		$actual = self::$lss->check_pw_grace_period($this->user->ID);
		$expect = self::$lss->options['pw_change_grace_period_minutes'] * 60;
		$this->assertSame($expect, $actual, 'Bad return value.');
	}

	/**
	 * @depends test_check_pw_grace_period__in_effect
	 */
	public function test_check_pw_grace_period__expired() {
		$options = self::$lss->options;
		$options['pw_change_grace_period_minutes'] = -1;
		self::$lss->options = $options;

		$actual = self::$lss->check_pw_grace_period($this->user->ID);
		$this->assertFalse($actual, 'Bad return value.');
	}

	public function test_delete_pw_grace_period__cleanup() {
		$actual = self::$lss->delete_pw_grace_period($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/*
	 * CHECK STATUS
	 */

	public function test_check__empty_user() {
		$actual = self::$lss->check(array(), null);
		$this->assertFalse($actual, 'Bad return value.');
	}

	public function test_check__pre_expiration() {
		$actual = self::$lss->check(array(), $this->user);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_get_pw_changed_time__something
	 */
	public function test_check__post_expiration_first() {
		$options = self::$lss->options;
		$options['pw_change_days'] = -1;
		self::$lss->options = $options;

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=login&'
				. self::$lss->key_login_msg . '=pw_grace';

		$actual = self::$lss->check(array(), $this->user);

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');

		$this->assertSame(-1, $actual, 'Bad return value.');
	}

	/**
	 * @depends test_get_pw_changed_time__something
	 */
	public function test_check__post_expiration_grace_expired() {
		$options = self::$lss->options;
		$options['pw_change_days'] = -1;
		$options['pw_change_grace_period_minutes'] = -1;
		self::$lss->options = $options;

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?action=retrievepassword&'
				. self::$lss->key_login_msg . '=pw_expired';

		$actual = self::$lss->check(array(), $this->user);

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');

		$this->assertSame(-2, $actual, 'Bad return value.');
	}

	public function test_redirect_to_login__other() {
		$_SERVER['REQUEST_URI'] = '/some/page';

		$expected_error = 'Cannot modify header information';
		$this->expected_errors($expected_error);
		self::$location_expected = get_option('siteurl')
				. '/wp-login.php?redirect_to=%2Fsome%2Fpage&action=acti%26n&'
				. self::$lss->key_login_msg . '=me%26g';

		self::$lss->redirect_to_login('me&g', true, 'acti&n');

		$this->assertTrue($this->were_expected_errors_found(),
				"Expected error not found: '$expected_error'");
		$this->assertEquals(self::$location_expected, self::$location_actual,
				'wp_redirect() produced unexpected location header.');
	}
}
