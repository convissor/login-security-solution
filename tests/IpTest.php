<?php

/**
 * Test IP related methods
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
 * Test IP related methods
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class IpTest extends TestCase {
	public static function setUpBeforeClass() {
		parent::$db_needed = false;
		parent::set_up_before_class();
	}


	public function data_ipv4() {
		return array(
			array('good' => array('1.2.3.4' => '1.2.3.4')),
			array('zerofill' => array('005.006.007.008' => '5.6.7.8')),
			array('big' => array('1.256.3.4' => '')),
			array('short' => array('1.2.3' => '')),
			array('long' => array('1.2.3.4.5' => '')),
			array('text' => array('abcd' => '')),
			array('empty' => array('' => '')),
			array('trim empty' => array('  ' => '')),
		);
	}

	public function data_ipv6() {
		return array(
			array('good' => array('1:2:3:4:5:6:7:8' => '1:2:3:4:5:6:7:8')),
			array('zerofill' => array('01:002:0003:4:5:6:7:8' => '1:2:3:4:5:6:7:8')),
			array('hex' => array('FFFF:D1D1:3:4:5:6:7:8' => 'ffff:d1d1:3:4:5:6:7:8')),
			// Not a kosher input format, but make it work anyway.
			array('compress mid 1' => array('1:2:3:4::6:7:8' => '1:2:3:4:0:6:7:8')),
			array('compress mid 2' => array('1:2:3::6:7:8' => '1:2:3:0:0:6:7:8')),
			array('compress mid 3' => array('1:2::6:7:8' => '1:2:0:0:0:6:7:8')),
			// Not a kosher input format, but make it work anyway.
			array('compress left 1' => array('::2:3:4:5:6:7:8' => '0:2:3:4:5:6:7:8')),
			array('compress left 2' => array('::3:4:5:6:7:8' => '0:0:3:4:5:6:7:8')),
			array('compress left 3' => array('::4:5:6:7:8' => '0:0:0:4:5:6:7:8')),
			// Not a kosher input format, but make it work anyway.
			array('compress mid 1' => array('1:2:3:4::6:7:8' => '1:2:3:4:0:6:7:8')),
			array('compress right 1' => array('1:2:3:4:5:6:7::' => '1:2:3:4:5:6:7:0')),
			array('compress right 2' => array('1:2:3:4:5:6::' => '1:2:3:4:5:6:0:0')),
			array('compress right 3' => array('1:2:3:4:5::' => '1:2:3:4:5:0:0:0')),
			array('too many 1' => array('1:2:3:4:5:6:7:8:9' => '')),
			array('too few 1' => array('1:2:3:4:5:6:7' => '')),
			array('too few 2' => array('1:2:3:4:5:6' => '')),
			array('too many compressions' => array('1:2:::8' => '')),
			array('empty' => array('' => '')),
			array('unspecified' => array('::' => '')),
			array('text' => array('abcd' => '')),
			array('hextobig' => array('FFFF:D1D1D1:3:4:5:6:7:8' => '')),
			array('inttobig' => array('FFFF:D1D1:3:40000:5:6:7:8' => '')),
			array('embed compat' => array('::1.2.3.4' => '0:0:0:0:0:0:1.2.3.4')),
			array('embed compat filled' => array('0:0:0:0:0:0:1.2.3.4' => '0:0:0:0:0:0:1.2.3.4')),
			array('embed map' => array('::ffff:1.2.3.4' => '0:0:0:0:0:ffff:1.2.3.4')),
			array('embed bad prefix' => array('::acac:1.2.3.4' => '')),
			array('embed map bad 4' => array('::ffff:1.2.666.4' => '')),
		);
	}

	/**
	 * @dataProvider data_ipv4
	 */
	public function test_normalize_ipv4($data) {
		list($input, $expect) = each($data);
		$actual = self::$lss->normalize_ipv4($input);
		$this->assertEquals($expect, $actual);
	}
	/**
	 * @dataProvider data_ipv6
	 */
	public function test_normalize_ipv6($data) {
		list($input, $expect) = each($data);
		$actual = self::$lss->normalize_ipv6($input);
		$this->assertEquals($expect, $actual);
	}

	/**#@+
	 * get_ip()
	 */
	/**
	 * @dataProvider data_ipv4
	 */
	public function test_get_ip__ipv4($data) {
		list($input, $expect) = each($data);
		$_SERVER['REMOTE_ADDR'] = $input;
		$actual = self::$lss->get_ip();
		$this->assertEquals($expect, $actual);
	}
	public function test_get_ip__ipv4_array() {
		$_SERVER['REMOTE_ADDR'] = array('foo');
		$actual = self::$lss->get_ip();
		$this->assertEquals('', $actual);
	}
	/**
	 * @dataProvider data_ipv6
	 */
	public function test_get_ip__ipv6($data) {
		list($input, $expect) = each($data);
		$_SERVER['REMOTE_ADDR'] = $input;
		$actual = self::$lss->get_ip();
		$this->assertEquals($expect, $actual);
	}
	/**#@- **/

	/**#@+
	 * get_network_ip()
	 */
	public function test_get_network_ip__empty() {
		$_SERVER['REMOTE_ADDR'] = '';
		$actual = self::$lss->get_network_ip();
		$this->assertEquals('', $actual);
	}
	public function test_get_network_ip__array_remote() {
		$_SERVER['REMOTE_ADDR'] = array('1.2.3.4');
		$actual = self::$lss->get_network_ip();
		$this->assertEquals('', $actual);
	}
	public function test_get_network_ip__array_param() {
		$actual = self::$lss->get_network_ip(array('1.2.3.4'));
		$this->assertEquals('', $actual);
	}
	public function test_get_network_ip__ipv4() {
		$actual = self::$lss->get_network_ip('1.2.3.4');
		$this->assertEquals('1.2.3', $actual);
	}
	public function test_get_network_ip__ipv4_remote_addr() {
		$_SERVER['REMOTE_ADDR'] = '1.2.3.4';
		$actual = self::$lss->get_network_ip();
		$this->assertEquals('1.2.3', $actual);
	}
	public function test_get_network_ip__ipv6() {
		$actual = self::$lss->get_network_ip('1:2:3:4:5:6:7:8');
		$this->assertEquals('1:2:3:4', $actual);
	}
	public function test_get_network_ip__ipv6_remote_addr() {
		$_SERVER['REMOTE_ADDR'] = '1:2:3:4:5:6:7:8';
		$actual = self::$lss->get_network_ip();
		$this->assertEquals('1:2:3:4', $actual);
	}
	/**#@- **/
}
