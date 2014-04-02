<?php

/**
 * Get the class we will use for testing
 */
require_once dirname(__FILE__) .  '/TestCase.php';

/**
 * Test the last login and message functionality
 *
 * @package login-security-solution
 * @author
 * @copyright
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class LastLoginTest extends TestCase {
	protected static $user_ID;


	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}


	public function test_get_last_login__empty_1() {
		$actual = self::$lss->get_last_login($this->user->ID);
		$this->assertSame(0, $actual);
	}

	public function test_set_last_login__add() {
		$actual = self::$lss->set_last_login($this->user->ID);
		$this->assertInternalType('integer', $actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_last_login__add
	 */
	public function test_set_last_login__update() {
		sleep(1);
		$actual = self::$lss->set_last_login($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_set_last_login__update
	 */
	public function test_get_last_login__something() {
		$actual = self::$lss->get_last_login($this->user->ID);
		$diff = (time() - $actual) < 1;
		$this->assertGreaterThanOrEqual(0,  $diff, 'Time was too long ago.');
		$this->assertLessThanOrEqual(1, $diff, 'Time was in the future.');
	}


	public function test_add_to_message_queue__add() {
		global $user_ID;
		$user_ID = $this->user->ID;
		$message = 'foo';
		$actual = self::$lss->add_to_message_queue($message);
		$this->assertInternalType('integer', $actual, 'Bad return value.');
	}

	/**
	 * @depends test_add_to_message_queue__add
	 */
	public function test_add_to_message_queue__update() {
		sleep(1);
		$message = 'bar';
		$actual = self::$lss->add_to_message_queue($message);
		$this->assertTrue($actual, 'Bad return value.');
	}

	/**
	 * @depends test_add_to_message_queue__update
	 */
	public function test_display_admin_notices__display() {
		sleep(1);
		$queue = (array) get_user_meta($this->user->ID, self::$lss->umk_message_queue);
		$this->assertSame(2, count($queue[0]));
		$actual = self::$lss->display_admin_notices_in_queue();
		$test_data = '<div class="updated"><p>foo</p></div><div class="updated"><p>bar</p></div>';
		$this->assertSame($test_data, $actual);
	}

	/**
	 * @depends test_display_admin_notices__display
	 */
	public function test_display_admin_notices__delete_queue() {
		sleep(1);
		$actual = self::$lss->get_message_queue($this->user->ID);
		$this->assertSame(0, count($actual));
	}

	/**
	 * @depends test_set_last_login__update
	 */
	public function test_push_last_login_to_message_queue__adds_message() {
		$time = self::$lss->get_last_login($this->user->ID);
		$date_value  = date_i18n( "F j, Y g:i a T", $time, true );
		$expected_message = sprintf(__("Welcome back. Last logged in %s", self::ID), $date_value);
		$actual = self::$lss->push_last_login_to_message_queue($this->user->ID);
		$this->assertTrue($actual, 'Bad return value.');
		$message_queue = self::$lss->get_message_queue($this->user->ID);
		$this->assertSame(1, count($message_queue));
		$this->assertSame($expected_message, $message_queue[0]);
	}

	/**
	 * @depends test_push_last_login_to_message_queue__adds_message
	 */
	public function test_push_last_login_to_message_queue__update() {
		$before_time = self::$lss->get_last_login($this->user->ID);
		self::$lss->push_last_login_to_message_queue($this->user->ID);
		$after_time = self::$lss->get_last_login($this->user->ID);
		$diff = ($after_time - $before_time) < 1;
		$this->assertGreaterThanOrEqual(0,  $diff, 'Time was too long ago.');
		$this->assertLessThanOrEqual(1, $diff, 'Time was in the future.');
	}


}
