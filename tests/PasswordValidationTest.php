<?php

/**
 * Test the password validation functionality
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
 * Test the password validation functionality
 *
 * @package login-security-solution
 * @author Daniel Convissor <danielc@analysisandsolutions.com>
 * @copyright The Analysis and Solutions Company, 2012
 * @license http://www.gnu.org/licenses/gpl-2.0.html GPLv2
 */
class PasswordValidationTest extends TestCase {
	protected static $dict_available;
	protected static $grep_available;
	protected static $mbstring_available;


	public static function setUpBeforeClass() {
		parent::$db_needed = false;
		parent::set_up_before_class();

		if (self::$lss->is_pw_dict_program('zygote')) {
			self::$dict_available = true;
		}
		if (self::$lss->is_pw_dictionary__grep('Pa$$w0rd1')) {
			self::$grep_available = true;
		}
		self::$mbstring_available = extension_loaded('mbstring');
	}

	public function setUp() {
		parent::setUp();
		self::$lss->available_mbstring = extension_loaded('mbstring');

		$options = self::$lss->options;
		$options['pw_complexity_exemption_length'] = 20;
		$options['pw_length'] = 8;
		self::$lss->options = $options;

		self::$lss->available_dict = self::$dict_available;
		self::$lss->available_grep = self::$grep_available;
		self::$lss->available_mbstring = self::$mbstring_available;
	}


	protected function err($message) {
		return self::$lss->err($message);
	}


	public function test_is_pw_dictionary__grepavail() {
		if (!self::$dict_available) {
			$this->markTestSkipped('grep not available');
		}
		self::$lss->available_grep = true;
		$actual = self::$lss->is_pw_dictionary('Pa$$w0rd1');
		$this->assertTrue($actual);
	}

	public function test_is_pw_dictionary__grepunavail() {
		self::$lss->available_grep = false;
		$actual = self::$lss->is_pw_dictionary('Pa$$w0rd1');
		$this->assertTrue($actual);
	}


	public function test_dict_program__unavailable() {
		self::$lss->available_dict = false;
		$actual = self::$lss->is_pw_dict_program('foo');
		$this->assertNull($actual);
	}

	public function test_dict_program_false() {
		if (!self::$dict_available) {
			$this->markTestSkipped('dict is not available');
		}
		$tests = array(
			"thiscannotbeaword",
			"简化字的昨天今天和明天",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_dict_program($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_dict_program_true() {
		if (!self::$dict_available) {
			$this->markTestSkipped('dict is not available');
		}
		$tests = array(
			"password",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_dict_program($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_dictionary__grep_unavailable() {
		self::$lss->available_grep = false;
		$actual = self::$lss->is_pw_dictionary__grep('foo');
		$this->assertNull($actual);
	}

	public function test_dictionary__file_false() {
		if (!self::$grep_available) {
			$this->markTestSkipped('grep is not available');
		}
		$tests = array(
			"thiscannotbeaword",
			"化字的昨天今天和明",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_dictionary__file($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_dictionary__file_true() {
		if (!self::$grep_available) {
			$this->markTestSkipped('grep is not available');
		}
		$tests = array(
			'Pa$$w0rd1',
			"简化字的昨天今天和明天",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_dictionary__file($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_dictionary__grep_false() {
		if (!self::$grep_available) {
			$this->markTestSkipped('grep is not available');
		}
		$tests = array(
			"thiscannotbeaword",
			"化字的昨天今天和明",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_dictionary__grep($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_dictionary__grep_true() {
		if (!self::$grep_available) {
			$this->markTestSkipped('grep is not available');
		}
		$tests = array(
			'Pa$$w0rd1',
			"简化字的昨天今天和明天",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_dictionary__grep($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_like_bloginfo_false() {
		$tests = array(
			"zzzzzzzzz",
			"简化字的昨天今天和明天",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_like_bloginfo($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_like_bloginfo_true() {
		$tests = array(
			get_bloginfo('name'),
			'othertextwith' . get_bloginfo('name'),
			get_bloginfo('url'),
			'othertextwith' . get_bloginfo('url'),
			get_bloginfo('description'),
			'othertextwith' . get_bloginfo('description'),
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_like_bloginfo($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_like_user_data_false() {
		$tests = array(
			"yyyy",
			"简字昨今和天",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_like_user_data($pw, $this->user);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_like_user_data_true() {
		$tests = array(
			"aaaa",
			"bbbbbbbb",
			"cccccccc",
			"dddddddd",
			"eeeeeeee",
			"ffff",
			"简化字的昨天今天和明天",
			"hhhh",
			"iiii",
			"jjjj",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_like_user_data($pw, $this->user);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_outside_ascii_false() {
		$tests = array(
			"aba!123",
			"aba~123",
			"aba 123",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_outside_ascii($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_outside_ascii_true() {
		$tests = array(
			"aba\n123",
			"简化字的昨天今天和明天",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_outside_ascii($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_missing_numeric_false() {
		$tests = array(
			"aA1!",
			"123",
			"ةيب8رعلا",
			"a२c",  // Devanagari number 2.
			"a୨c",  // Oriya number 2.
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_numeric($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_missing_numeric_true() {
		$tests = array(
			"abc",
			"ABC",
			"!@#",
			"aAb",
			"a!a!",
			"A!A!",
			"aA!",
			"aבc",  // Hebrew letter number 2.
			"ةيبرعلا",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_numeric($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_missing_punct_chars_false() {
		$tests = array(
			"aA1!",
			"#",
			".",
			"Россия.",
			"「中國哲學史大綱」、胡適",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_punct_chars($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_missing_punct_chars_true() {
		$tests = array(
			"123",
			"abc",
			"ABC",
			"aAb",
			"a1a",
			"aA1",
			"a",
			"A",
			"1",
			"Россия",
			"中國哲學史大綱胡適",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_punct_chars($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_missing_upper_lower_chars_false() {
		$tests = array(
			"aA1!",
			"aAb",
			"aA!",
		);

		if (self::$mbstring_available) {
			$tests[] = "БбƤƥ";  // Bicameral UTF-8.
			$tests[] = "חح";  // Unicameral UTF-8.
		}

		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_upper_lower_chars($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_missing_upper_lower_chars_true() {
		$tests = array(
			"123",
			"abc",
			"ABC",
			"!@#",
			"a1a",
			"a!a!",
			"A!A!",
			"a1!",
			"A1!",
			"бƥ",
			"БƤ",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_upper_lower_chars($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_missing_upper_lower_chars_false__nomb() {
		self::$lss->available_mbstring = false;
		$tests = array(
			"aA1!",
			"aAb",
			"aA!",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_upper_lower_chars($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}

	public function test_missing_upper_lower_chars_true__nomb() {
		self::$lss->available_mbstring = false;
		$tests = array(
			"123",
			"abc",
			"ABC",
			"!@#",
			"a1a",
			"a!a!",
			"A!A!",
			"a1!",
			"A1!",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_missing_upper_lower_chars($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_sequential_codepoints_false() {
		$tests = array(
			"agke58#",
			"תירִבְעִ",
			"ⲘⲉⲧⲢⲉⲙ̀ⲛⲭⲏⲙⲓ",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_sequential_codepoints($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_sequential_codepoints_true() {
		$tests = array(
			"1234",
			"abcd",
			"ABCD",
			"%&'(",
			"דגבא",
			"ϣϥϧ",
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_sequential_codepoints($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_sequential_file_false() {
		$tests = array(
			"1357",
			"adg!#%135yip579",  // not sequential
			"adg!#%135yu579",  // "yu" is sequential, but too short
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_sequential_file($pw);
			$this->assertFalse($actual, "Should have passed: '$pw'");
		}
	}
	public function test_sequential_file_true() {
		$tests = array(
			"^&*()",
			"asdf",
			"QWERT",
			"fdsa",
			"adg!#%135yui579",  // "yui" is sequential
			"adg!#%135iuy579",  // "iuy" is "yui" sequence reversed
		);
		foreach ($tests as $pw) {
			$actual = self::$lss->is_pw_sequential_file($pw);
			$this->assertTrue($actual, "Should have failed: '$pw'");
		}
	}

	public function test_split_types_default3() {
		$tests = array(
			"^&*()" => array("^&*()"),
			"ad" => array("ad"),
			"asd" => array("asd"),
			"1234" => array("1234"),
			"adgi!15yYui5889" => array("adgi", "yYui", "5889"),
			"adgi!1365yYui5" => array("adgi", "1365", "yYui"),
			"adgi!1365yYui59" => array("adgi", "1365", "yYui"),
			"adgi 1365 yYui" => array("adgi", "1365", "yYui"),
			"adgi song yYui" => array("adgi", "song", "yYui"),
		);
		foreach ($tests as $pw => $expected) {
			$actual = self::$lss->split_types($pw);
			$this->assertEquals($expected, $actual);
		}
	}

	public function test_split_types_5() {
		$tests = array(
			"^&*()" => array("^&*()"),
			"ad" => array("ad"),
			"asd" => array("asd"),
			"1234" => array("1234"),
			"adgiii!.^#--?133655yaaYui" => array("adgiii", "!.^#--?", "133655", "yaaYui"),
			"adgi!13355yYui59" => array("13355"),
		);
		foreach ($tests as $pw => $expected) {
			$actual = self::$lss->split_types($pw, 5);
			$this->assertEquals($expected, $actual);
		}
	}

	public function test_strip_nonword_chars() {
		$tests = array(
			"^a&*b()c2" => "abc2",
			"「中國哲學史大綱」、胡適" => "中國哲學史大綱胡適",
			"2חַ״וּדּ" => "2חוד",
		);
		foreach ($tests as $in => $expect) {
			$actual = self::$lss->strip_nonword_chars($in);
			$this->assertEquals($expect, $actual);
		}
	}


	public function test_validate_pw__notset() {
		$errors = new WP_Error;
		$user = new stdClass;
		$actual = self::$lss->validate_pw($user, $errors);
		$this->assertFalse($actual,
				"password not being set should have failed.");
		$this->assertEquals(
			$this->err(__("Password not set.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__array() {
		$errors = new WP_Error;
		$actual = self::$lss->validate_pw(array('abc'), $errors);
		$this->assertFalse($actual,
				"'array('abc')' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords must be strings.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__ascii() {
		self::$lss->available_mbstring = false;

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords must use ASCII characters.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__short_mb() {
		if (!self::$mbstring_available) {
			$this->markTestSkipped('mbstring not available');
		}

		$this->user->user_pass = '简化字的昨天今';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Password is too short.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__short_nomb() {
		self::$lss->available_mbstring = false;
		$this->user->user_pass = 'aA1!';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Password is too short.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__nopunct() {
		$this->user->user_pass = '123456789012';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
				$this->err(sprintf(__("Passwords must either contain punctuation marks / symbols or be %d characters long.", self::ID), self::$lss->options['pw_complexity_exemption_length'])),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__nonumbers() {
		$this->user->user_pass = 'axj*@UXyqy';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
					$this->err(sprintf(__("Passwords must either contain numbers or be %d characters long.", self::ID), self::$lss->options['pw_complexity_exemption_length'])),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__noupperlower() {
		$this->user->user_pass = 'axj*1@yqy';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
					$this->err(sprintf(__("Passwords must either contain upper-case and lower-case letters or be %d characters long.", self::ID), self::$lss->options['pw_complexity_exemption_length'])),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__sequentialfile() {
		$this->user->user_pass = 'alGb02i&*()';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords can't be sequential keys.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__sequentialcodepoints() {
		$this->user->user_pass = 'abAB12!@';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords can't have that many sequential characters.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__userdata() {
		$this->user->user_pass = $this->user->nickname;

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords can't contain user data.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__userdata_leet() {
		$this->user->user_pass = 'this@@@@ShouldGetNa1led';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords can't contain user data.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__bloginfo() {
		$this->user->user_pass = 'Ja!k2' . get_bloginfo('description');

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords can't contain site info.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__dictionary() {
		$this->user->user_pass = 'Pa$$w0rd1';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Password is too common.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__dict() {
		if (!self::$dict_available) {
			$this->markTestSkipped('grep not available');
		}
		$this->user->user_pass = 'R3n0vat!on';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertFalse($actual,
				"'" . $this->user->user_pass . "' should have failed.");
		$this->assertEquals(
			$this->err(__("Passwords can't be variations of dictionary words.", self::ID)),
			$errors->get_error_message()
		);
	}

	public function test_validate_pw__good() {
		if (!self::$mbstring_available) {
			$this->user->user_pass = 'Some ASCII Only PW 4 You!';
		}

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertTrue($actual,
				"'" . $this->user->user_pass . "' should have passed, but got: "
				. $errors->get_error_message());
		$this->assertEmpty($errors->get_error_message());
	}

	public function test_validate_pw__good_complex_exempt() {
		$this->user->user_pass = 'this is a very long password not complex';

		$errors = new WP_Error;
		$actual = self::$lss->validate_pw($this->user, $errors);
		$this->assertTrue($actual,
				"'" . $this->user->user_pass . "' should have passed, but got: "
				. $errors->get_error_message());
		$this->assertEmpty($errors->get_error_message());
	}

	public function test_has_match_array() {
		$actual = self::$lss->has_match('foo', array());
		$this->assertFalse($actual);
	}

	public function test_has_match_empty() {
		$actual = self::$lss->has_match('foo', '');
		$this->assertFalse($actual);
	}
}
