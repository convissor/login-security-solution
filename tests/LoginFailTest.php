<?php

/**
 * Test login failure and lockout functionality
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
 * Test login failure and lockout functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class LoginFailTest extends TestCase {
	protected $ip;
	protected $network_ip;
	protected $user_name;
	protected $pass_md5;


	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}

	public function setUp() {
		parent::setUp();

		if (!$this->is_fail_table_configured()) {
			$this->markTestSkipped("The " . self::$lss->table_fail . " table doesn't exist or isn't using the InnoDB engine. Probably the plugin hasn't been activated.");
		}

		$this->ip = '1.2.38.4';
		$_SERVER['REMOTE_ADDR'] = $this->ip;
		$this->network_ip = '1.2.38';

		$this->user_name = 'test';
		$this->pass_md5 = 'ababab';

		$options = self::$lss->options;
		$options['login_fail_minutes'] = 60;
		$options['login_fail_notify'] = 4;
		$options['login_fail_notify_multiple'] = 0;
		$options['login_fail_tier_2'] = 3;
		$options['login_fail_tier_3'] = 4;
		$options['login_fail_breach_notify'] = 4;
		$options['login_fail_breach_pw_force_change'] = 4;
		self::$lss->options = $options;

		self::$lss->user_pass = 'some password';
	}


	/*
	 * LOGIN FAIL
	 */

	public function test_insert_fail() {
		self::$lss->insert_fail($this->ip, $this->user_name, $this->pass_md5);
		$this->check_fail_record($this->ip, $this->user_name, $this->pass_md5);

		self::$lss->insert_fail($this->ip, $this->user_name, 'other md5');
		$this->check_fail_record($this->ip, $this->user_name, 'other md5');
	}

	/**
	 * @depends test_insert_fail
	 */
	public function test_is_login_fail_exact_match() {
		$actual = self::$lss->is_login_fail_exact_match($this->ip, $this->user_name, $this->pass_md5);
		$this->assertTrue($actual, 'Expect match.');

		$actual = self::$lss->is_login_fail_exact_match($this->ip, $this->user_name, 'no match');
		$this->assertFalse($actual, 'Expect no match.');
	}

	/**
	 * @depends test_insert_fail
	 */
	public function test_get_login_fail() {
		$expected = array(
			'total' => '2',
			'network_ip' => '2',
			'user_name' => '2',
			'pass_md5' => '1',
		);

		$actual = self::$lss->get_login_fail($this->network_ip,
				$this->user_name, $this->pass_md5);

		$this->assertEquals($expected, $actual);
	}

	/**
	 * @depends test_get_login_fail
	 */
	public function test_get_login_fail_shorter_network() {
		$expected = array(
			'total' => '0',
			'network_ip' => null,
			'user_name' => null,
			'pass_md5' => null,
		);

		$actual = self::$lss->get_login_fail('1.2.3', 'nunca', 'nada');

		$this->assertEquals($expected, $actual);
	}

	/**
	 * @depends test_insert_fail
	 */
	public function test_get_login_fail__empty_ip() {
		global $wpdb;

		$expected = array(
			'total' => '3',
			'network_ip' => '1',
			'user_name' => '3',
			'pass_md5' => '2',
		);

		$wpdb->query('SAVEPOINT pre_threshold');

		self::$lss->insert_fail('', $this->user_name, $this->pass_md5);
		$this->check_fail_record('', $this->user_name, $this->pass_md5);

		$actual = self::$lss->get_login_fail('',
				$this->user_name, $this->pass_md5);

		$this->assertEquals($expected, $actual);

		$wpdb->query('ROLLBACK TO pre_threshold');
	}

	/*
	 * PROCESS LOGIN FAIL
	 */

	/**
	 * @depends test_get_login_fail
	 */
	public function test_process_login_fail__pre_threshold() {
		global $wpdb;

		$sleep = self::$lss->process_login_fail($this->user_name, 'reed');
		$this->assertGreaterThan(0, $sleep, 'Sleep was not set.');

		$this->assertInternalType('integer', $wpdb->insert_id,
				'This should be an insert id.');
	}

	/**
	 * @depends test_get_login_fail
	 */
	public function test_process_login_fail__exact_match() {
		global $wpdb;

		$actual = self::$lss->process_login_fail($this->user_name, 'reed');
		$this->assertEquals(-4, $actual);
	}

	public function test_wp_login__null() {
		$actual = self::$lss->wp_login(null, null);
		$this->assertEquals(-3, $actual);
	}

	/**
	 * @depends test_process_login_fail__pre_threshold
	 */
	public function test_wp_login__pre_breach_threshold() {
		$actual = self::$lss->wp_login(null, $this->user);
		$flag = login_security_solution::LOGIN_UNKNOWN_IP;
		$this->assertSame($flag + 1, $actual, 'wp_login() return value...');
		$this->assertGreaterThan(0, self::$lss->sleep, 'Sleep not set.');

		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual, 'get_pw_force_change() return value...');
	}

	/**
	 * @depends test_process_login_fail__pre_threshold
	 */
	public function test_process_login_fail__post_threshold() {
		global $wpdb;

		$wpdb->query('SAVEPOINT pre_post_threshold');

		self::$mail_file_basename = __METHOD__;

		try {
			// Do THE deed.
			$sleep = self::$lss->process_login_fail($this->user_name, $this->pass_md5);
			// Count is now 4.
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}

		$wpdb->query('ROLLBACK TO pre_post_threshold');
		// Count is now 3.

		$this->check_mail_file();
		$this->assertGreaterThan(0, $sleep, 'Sleep was not set.');
	}

	/**
	 * @depends test_process_login_fail__post_threshold
	 */
	public function test_process_login_fail__post_threshold_force_change_off() {
		self::$mail_file_basename = __METHOD__;

		$options = self::$lss->options;
		$options['login_fail_breach_pw_force_change'] = 0;
		self::$lss->options = $options;

		try {
			// Do THE deed.
			$sleep = self::$lss->process_login_fail($this->user_name, $this->pass_md5);
			// Count is now 4.
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}

		$this->check_mail_file();
		$this->assertGreaterThan(0, $sleep, 'Sleep was not set.');
	}

	/**
	 * @depends test_process_login_fail__post_threshold_force_change_off
	 */
	public function test_process_login_fail__post_threshold_not_modulus() {
		global $wpdb;

		$wpdb->query('SAVEPOINT pre_not_modulus');

		try {
			// Do THE deed.
			$sleep = self::$lss->process_login_fail($this->user_name, __FUNCTION__);
			// Count is now 5.
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$this->assertGreaterThan(0, $sleep, 'Sleep was not set.');
	}

	/**
	 * @depends test_process_login_fail__post_threshold_not_modulus
	 */
	public function test_process_login_fail__post_threshold_multiple_on() {
		global $wpdb;

		$wpdb->query('SAVEPOINT pre_multiple');

		self::$mail_file_basename = __METHOD__;

		$options = self::$lss->options;
		$options['login_fail_notify'] = 2;
		$options['login_fail_notify_multiple'] = 1;
		self::$lss->options = $options;

		try {
			// Do THE deed.
			$sleep = self::$lss->process_login_fail($this->user_name, __FUNCTION__);
			// Count is now 6.
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}

		$this->check_mail_file();
		$this->assertGreaterThan(0, $sleep, 'Sleep was not set.');

		$wpdb->query('ROLLBACK TO pre_multiple');
		// Count is now 5.
	}

	/**
	 * @depends test_process_login_fail__post_threshold_multiple_on
	 */
	public function test_process_login_fail__post_threshold_multiple_off() {
		global $wpdb;

		$options = self::$lss->options;
		$options['login_fail_notify'] = 2;
		self::$lss->options = $options;

		try {
			// Do THE deed.
			$sleep = self::$lss->process_login_fail($this->user_name, __FUNCTION__);
			// Count is now 6.
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$this->assertGreaterThan(0, $sleep, 'Sleep was not set.');

		$wpdb->query('ROLLBACK TO pre_not_modulus');
	}

	/**
	 * @depends test_process_login_fail__post_threshold_multiple_off
	 */
	public function test_wp_login__post_breach_threshold() {
		self::$mail_file_basename = __METHOD__;

		try {
			// Do THE deed.
			$actual = self::$lss->wp_login(null, $this->user);
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$flag = login_security_solution::LOGIN_UNKNOWN_IP
				+ login_security_solution::LOGIN_FORCE_PW_CHANGE
				+ login_security_solution::LOGIN_NOTIFY;
		$this->assertSame($flag + 1, $actual, 'wp_login() return value...');
		$this->assertGreaterThan(0, self::$lss->sleep, 'Sleep not set.');

		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertTrue($actual, 'get_pw_force_change() return value...');

		self::$lss->delete_pw_force_change($this->user->ID);

		$this->check_mail_file();
	}

	/**
	 * @depends test_wp_login__post_breach_threshold
	 */
	public function test_wp_login__post_breach_threshold_verified_ip() {
		global $wpdb;

		$wpdb->query('SAVEPOINT pre_verified_ip');

		$this->ip = '1.2.33.4';
		$_SERVER['REMOTE_ADDR'] = $this->ip;
		$this->network_ip = '1.2.33';

		self::$lss->save_verified_ip($this->user->ID, $this->ip);

		try {
			// Do THE deed.
			$actual = self::$lss->wp_login(null, $this->user);
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$flag = login_security_solution::LOGIN_VERIFIED_IP;
		$this->assertSame($flag + 1, $actual, 'wp_login() return value...');
		$this->assertNull(self::$lss->sleep, 'Sleep should be unset.');

		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual, 'get_pw_force_change() return value...');

		$wpdb->query('ROLLBACK TO pre_verified_ip');
	}

	/**
	 * @depends test_wp_login__post_breach_threshold_verified_ip
	 */
	public function test_wp_login__post_breach_threshold_only_notify() {
		self::$mail_file_basename = __METHOD__;

		$options = self::$lss->options;
		$options['login_fail_breach_pw_force_change'] = 0;
		self::$lss->options = $options;

		self::$lss->delete_pw_force_change($this->user->ID);

		try {
			// Do THE deed.
			$actual = self::$lss->wp_login(null, $this->user);
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$flag = login_security_solution::LOGIN_UNKNOWN_IP
				+ login_security_solution::LOGIN_NOTIFY;
		$this->assertSame($flag + 1, $actual, 'wp_login() return value...');
		$this->assertGreaterThan(0, self::$lss->sleep, 'Sleep not set.');

		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual, 'get_pw_force_change() return value...');

		$this->check_mail_file();
	}

	/**
	 * @depends test_process_login_fail__post_threshold
	 */
	public function test_wp_login__post_breach_threshold_only_force() {
		$options = self::$lss->options;
		$options['login_fail_breach_notify'] = 0;
		self::$lss->options = $options;

		$this->ip = '1.2.38.4';
		$_SERVER['REMOTE_ADDR'] = $this->ip;
		$this->network_ip = '1.2.38';

		self::$lss->delete_pw_force_change($this->user->ID);

		try {
			// Do THE deed.
			$actual = self::$lss->wp_login(null, $this->user);
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$flag = login_security_solution::LOGIN_UNKNOWN_IP
				+ login_security_solution::LOGIN_FORCE_PW_CHANGE;
		$this->assertSame($flag + 1, $actual, 'wp_login() return value...');
		$this->assertGreaterThan(0, self::$lss->sleep, 'Sleep not set.');

		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertTrue($actual, 'get_pw_force_change() return value...');
	}

	/**
	 * @depends test_process_login_fail__post_threshold
	 */
	public function test_wp_login__post_breach_threshold_no_action() {
		$options = self::$lss->options;
		$options['login_fail_breach_notify'] = 0;
		$options['login_fail_breach_pw_force_change'] = 0;
		self::$lss->options = $options;

		self::$lss->delete_pw_force_change($this->user->ID);

		try {
			// Do THE deed.
			$actual = self::$lss->wp_login(null, $this->user);
		} catch (Exception $e) {
			$this->fail($e->getMessage());
		}
		$flag = login_security_solution::LOGIN_UNKNOWN_IP;
		$this->assertSame($flag + 1, $actual, 'wp_login() return value...');
		$this->assertGreaterThan(0, self::$lss->sleep, 'Sleep not set.');

		$actual = self::$lss->get_pw_force_change($this->user->ID);
		$this->assertFalse($actual, 'get_pw_force_change() return value...');
	}
}
