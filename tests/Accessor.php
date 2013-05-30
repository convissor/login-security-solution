<?php

/**
 * Extend the class to be tested, providing access to protected elements
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */

/**
 * Obtain the parent class.
 * Use dirname(dirname()) because safe mode can disable "../".
 */
require_once dirname(dirname(__FILE__)) . '/login-security-solution.php';

/**
 * Get the admin class
 */
require_once dirname(dirname(__FILE__)) .  '/admin.php';

/** Tell the system not to disconnect the database or do the slow downs. */
define('LOGIN_SECURITY_SOLUTION_TESTING', true);

/**
 * Extend the class to be tested, providing access to protected elements
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class Accessor extends login_security_solution_admin {
	public $time_overload = 10;

	public function __call($method, $args) {
		return call_user_func_array(array($this, $method), $args);
	}
	public function __get($property) {
		return $this->$property;
	}
	public function __set($property, $value) {
		$this->$property = $value;
	}
	public function get_data_element($key) {
		return $this->data[$key];
	}
	protected function get_time() {
		return $this->time_overload++;
	}
}
