<?php

/**
 * Test the login message filter
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
 * Test the login message filter
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class LoginMessageTest extends TestCase {
	public static function setUpBeforeClass() {
		parent::$db_needed = false;
		parent::set_up_before_class();
	}


	public function ours($ours) {
		return '<p class="login message">'
				. self::$lss->hsc_utf8($ours) . '</p>';
	}

	public function test_login_message__unset() {
		unset($_GET[self::$lss->key_login_msg]);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input', $actual, 'Output should not be modified.');
	}

	public function test_login_message__empty() {
		$_GET[self::$lss->key_login_msg] = '';

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input', $actual, 'Output should not be modified.');
	}

	public function test_login_message__bogus() {
		$_GET[self::$lss->key_login_msg] = 'ajkdslfasjdlfaskjdl';

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input', $actual, 'Output should not be modified.');
	}

	public function test_login_message__idle() {
		$_GET[self::$lss->key_login_msg] = 'idle';

		$value = 8;
		$options = self::$lss->options;
		$options['idle_timeout'] = $value;
		self::$lss->options = $options;

		$ours = sprintf(__('It has been over %d minutes since your last action.', self::ID), $value);
		$ours .= ' ' . __('Please log back in.', self::ID);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $this->ours($ours), $actual,
				'Output should have been modified.');
	}

	public function test_login_message__pw_expired() {
		$_GET[self::$lss->key_login_msg] = 'pw_expired';

		$ours = __('The grace period for changing your password has expired.', self::ID);
		$ours .= ' ' . __('Please submit this form to reset your password.', self::ID);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $this->ours($ours), $actual,
				'Output should have been modified.');
	}

	public function test_login_message__pw_force() {
		$_GET[self::$lss->key_login_msg] = 'pw_force';

		$ours = __('Your password must be reset.', self::ID);
		$ours .= ' ' . __('Please submit this form to reset it.', self::ID);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $this->ours($ours), $actual,
				'Output should have been modified.');
	}

	public function test_login_message__pw_grace() {
		$_GET[self::$lss->key_login_msg] = 'pw_grace';

		$value = 8;
		$options = self::$lss->options;
		$options['pw_change_grace_period_minutes'] = $value;
		self::$lss->options = $options;

		$ours = __('Your password has expired. Please log and change it.', self::ID);
		$ours .= ' ' . sprintf(__('We provide a %d minute grace period to do so.', self::ID), $value);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $this->ours($ours), $actual,
				'Output should have been modified.');
	}

	public function test_login_message__pw_reset_bad() {
		$_GET[self::$lss->key_login_msg] = 'pw-short';

		$ours = __("Password is too short.", self::ID);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $this->ours($ours), $actual,
				'Output should have been modified.');
	}

	public function test_login_message__disable_logins__no_key() {
		$_GET[self::$lss->key_login_msg] = '';

		$options = self::$lss->options;
		$options['disable_logins'] = 1;
		self::$lss->options = $options;

		$ours = __('The site is undergoing maintenance.', self::ID);
		$ours .= ' ' . __('Please try again later.', self::ID);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $this->ours($ours), $actual,
				'Output should have been modified.');
	}

	public function test_login_message__disable_logins__key() {
		$_GET[self::$lss->key_login_msg] = 'pw-ascii';

		$options = self::$lss->options;
		$options['disable_logins'] = 1;
		self::$lss->options = $options;

		$ours = __('The site is undergoing maintenance.', self::ID);
		$ours .= ' ' . __('Please try again later.', self::ID);
		$final = $this->ours($ours);

		$ours = __("Passwords must use ASCII characters.", self::ID);
		$final .= $this->ours($ours);

		$actual = self::$lss->login_message('input');
		$this->assertEquals('input' . $final, $actual,
				'Output should have been modified.');
	}
}
