<?php

/**
 * Test the verified IP saving and retrieving
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
 * Test the verified IP saving and retrieving
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class VerifiedIpTest extends TestCase {
	protected static $ip_1 = '1.2.3.4';


	public static function setUpBeforeClass() {
		parent::$db_needed = true;
		parent::set_up_before_class();
	}

	public function setUp() {
		parent::setUp();
		// Because arrays naturally start at index 0, force our IP array to
		// start indexing at 10 to ensure tests do what we really expect
		// than passing by getting lucky.
		self::$lss->time_overload = 10;
	}


	public function test_get_verified_ips__empty() {
		global $wpdb;

		$wpdb->query('SAVEPOINT empty');

		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertSame(array(), $actual);
	}

	public function test_save_verified_ip__non_array_edge_case() {
		update_user_meta($this->user->ID, self::$lss->umk_verified_ips, 'foo');

		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertEquals(array('foo'), $actual);

		delete_user_meta($this->user->ID, self::$lss->umk_verified_ips);
	}

	public function test_save_verified_ip__new() {
		$actual = self::$lss->save_verified_ip($this->user->ID, self::$ip_1);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_save_verified_ip__new
	 */
	public function test_save_verified_ip__exists() {
		$actual = self::$lss->save_verified_ip($this->user->ID, self::$ip_1);
		$this->assertTrue($actual);
	}

	/**
	 * @depends test_save_verified_ip__exists
	 */
	public function test_get_verified_ips__one() {
		global $wpdb;

		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertEquals(array(10 => self::$ip_1), $actual);

		$wpdb->query('ROLLBACK TO empty');
		wp_cache_init();

		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertSame(array(), $actual);
	}

	/**
	 * @depends test_get_verified_ips__one
	 */
	public function test_save_verified_ip__overflow() {
		global $wpdb;

		self::$lss->save_verified_ip($this->user->ID, 'a');
		self::$lss->save_verified_ip($this->user->ID, 'b');
		self::$lss->save_verified_ip($this->user->ID, 'c');
		self::$lss->save_verified_ip($this->user->ID, 'd');
		self::$lss->save_verified_ip($this->user->ID, 'e');
		self::$lss->save_verified_ip($this->user->ID, 'f');
		self::$lss->save_verified_ip($this->user->ID, 'g');
		self::$lss->save_verified_ip($this->user->ID, 'h');
		self::$lss->save_verified_ip($this->user->ID, 'i');
		self::$lss->save_verified_ip($this->user->ID, 'j');
		self::$lss->save_verified_ip($this->user->ID, 'k');
		self::$lss->save_verified_ip($this->user->ID, 'l');
		self::$lss->save_verified_ip($this->user->ID, 'm');
		self::$lss->save_verified_ip($this->user->ID, 'n');
		self::$lss->save_verified_ip($this->user->ID, 'o');
		self::$lss->save_verified_ip($this->user->ID, 'p');
		self::$lss->save_verified_ip($this->user->ID, 'q');
		self::$lss->save_verified_ip($this->user->ID, 'r');
		self::$lss->save_verified_ip($this->user->ID, 's');
		self::$lss->save_verified_ip($this->user->ID, 't');
		self::$lss->save_verified_ip($this->user->ID, 'u');

		$expected_keys = range(11, 30);
		$expected_values = range('b', 'u');
		$expected = array_combine($expected_keys, $expected_values);
		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertEquals($expected, $actual);

		$wpdb->query('ROLLBACK TO empty');
		wp_cache_init();
	}

	/**
	 * @depends test_save_verified_ip__overflow
	 */
	public function test_password_reset__normal() {
		global $wpdb;

		$ip = '3.4.5.6';
		$_SERVER['REMOTE_ADDR'] = $ip;

		$actual = self::$lss->password_reset($this->user, 'some 1 Needs!');
		$this->assertNull($actual, 'password_reset() should return null.');

		// Check the outcome.
		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertSame(array(10 => $ip), $actual, 'Expected IP was not found.');

		$wpdb->query('ROLLBACK TO empty');
		wp_cache_init();
	}

	/**
	 * @depends test_password_reset__normal
	 */
	public function test_profile_update__normal() {
		global $current_user;

		$ip = '4.5.6.7';
		$_SERVER['REMOTE_ADDR'] = $ip;
		// So user id = current user id in our profile update errors method.
		$current_user = $this->user;

		if (!extension_loaded('mbstring')) {
			$this->user->user_pass = 'Some ASCII Only PW 4 You!';
		}

		$errors = new WP_Error;
		$actual = self::$lss->user_profile_update_errors($errors, 1, $this->user);
		$this->assertTrue($actual, 'Bad return value.');

		// Check the outcome.
		$actual = self::$lss->get_verified_ips($this->user->ID);
		$this->assertSame(array(10 => $ip), $actual, 'Expected IP was not found.');
	}
}
