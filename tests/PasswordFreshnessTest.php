<?php

/**
 * Test the password expiration functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012-2014
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
 * @copyright The Analysis and Solutions Company, 2012-2014
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class PasswordFreshnessTest extends TestCase {
	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}

	public function setUp() {
		parent::setUp();

		$options = self::$lss->options;
		$options['pw_min_age_change_days'] = 10;
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
	 * IS EXPIRED
	 */

	public function test_is_pw_too_fresh__disabled() {
		$options = self::$lss->options;
		$options['pw_min_age_change_days'] = 0;
		self::$lss->options = $options;

		$actual = self::$lss->is_pw_too_fresh($this->user->ID);
		$this->assertNull($actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_pw_changed_time__add
	 * @depends test_get_pw_changed_time__something
	 */
	public function test_is_pw_too_fresh__new() {
		$actual = self::$lss->is_pw_too_fresh($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_is_pw_too_fresh__new
	 */
	public function test_is_pw_too_fresh__too_fresh() {
		$actual = self::$lss->is_pw_too_fresh($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_is_pw_too_fresh__new
	 */
	public function test_is_pw_expired__not_fresh() {
		$options = self::$lss->options;
		$options['pw_min_age_change_days'] = -1;
		self::$lss->options = $options;

		$actual = self::$lss->is_pw_too_fresh($this->user->ID);
		$this->assertFalse($actual, 'Bad return value.');
	}

}
