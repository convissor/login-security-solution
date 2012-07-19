<?php

/**
 * Test the login errors filter
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
 * Test the login errors filter
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class LoginErrorsTest extends TestCase {
	protected $ip;
	protected $network_ip;
	protected $user_name;
	protected $user_pass;
	protected $pass_md5;


	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}

	public function setUp() {
		global $errors;

		parent::setUp();

		$this->ip = '1.2.3.4';
		$_SERVER['REMOTE_ADDR'] = $this->ip;
		$this->network_ip = '1.2.3';

		$this->user_name = 'test';
		$this->user_pass = 'ababab';
		$this->pass_md5 = self::$lss->md5($this->user_pass);

		$options = self::$lss->options;
		$options['login_fail_minutes'] = 60;
		$options['login_fail_notify'] = 0;
		$options['login_fail_breach_notify'] = 0;
		self::$lss->options = $options;

		$errors = new WP_Error;
		$_POST['log'] = 'username';
		$_POST['pwd'] = $this->user_pass;
		unset($_REQUEST['action']);
	}

	protected function err($message) {
		return self::$lss->hsc_utf8($message);
	}


	public function test_login_errors__nothing() {
		global $errors, $user_name;

		$actual = self::$lss->login_errors('input');
		$this->assertEquals('input', $actual, 'Output should not be modified.');
		$this->assertArrayHasKey('log', $_POST, "POST log shouldn't be touched.");
	}

	public function test_login_errors__register() {
		global $errors, $user_name;

		$errors->add('invalid_username', 'blargh');
		$_REQUEST['action'] = 'register';

		$actual = self::$lss->login_errors('input');
		$this->assertEquals('input',
				$actual, 'Output should not be modified.');
		$this->assertArrayHasKey('log', $_POST, "POST log shouldn't be touched.");
	}

	public function test_login_errors__bad_name() {
		global $errors, $user_name;

		$errors->add('invalid_username', 'blargh');
		$user_name = $this->user_name;

		$actual = self::$lss->login_errors('input');

		$this->assertEquals(
				$this->err(__("Invalid username or password.", self::ID)),
				$actual, 'Output should have been modified.');
		$this->assertArrayNotHasKey('log', $_POST, "POST log should be unset.");
	}

	public function test_login_errors__bad_pw() {
		global $errors, $user_name;

		$errors->add('incorrect_password', 'blargh');
		$user_name = $this->user_name;

		$actual = self::$lss->login_errors('input');

		$this->assertEquals(
				$this->err(__("Invalid username or password.", self::ID)),
				$actual, 'Output should have been modified.');
		$this->assertArrayNotHasKey('log', $_POST, "POST log should be unset.");
	}

	public function test_login_errors__reset_bad_email() {
		global $errors, $user_name;

		$errors->add('invalid_email', 'blargh');

		$actual = self::$lss->login_errors('input');

		// This text is lifted directly from WordPress.
		$this->assertEquals(
				$this->err(__('Password reset is not allowed for this user')),
				$actual, 'Output should have been modified.');
		$this->assertArrayHasKey('log', $_POST, "POST log shouldn't be touched.");
	}

	public function test_login_errors__reset_bad_combo() {
		global $errors, $user_name;

		$errors->add('invalidcombo', 'blargh');

		$actual = self::$lss->login_errors('input');

		// This text is lifted directly from WordPress.
		$this->assertEquals(
				$this->err(__('Password reset is not allowed for this user')),
				$actual, 'Output should have been modified.');
		$this->assertArrayHasKey('log', $_POST, "POST log shouldn't be touched.");
	}
}
