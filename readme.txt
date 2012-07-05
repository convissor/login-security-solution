=== Login Security Solution ===
Contributors: convissor
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=danielc%40analysisandsolutions%2ecom&lc=US&item_name=Donate%3a%20Login%20Security%20Solution&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted
Tags: login, password, passwords, strength, strong, idle, timeout, maintenance, security, attack, hack, lock, ban
Requires at least: 3.3
Tested up to: 3.4.1
Stable tag: 0.13.0

Security against brute force attacks by tracking IP, name, password; requiring very strong passwords. Idle timeout. Maintenance mode. Multisite ready!


== Description ==

A simple way to lock down login security for multisite and regular
WordPress installations.

* Blocks brute force and dictionary attacks without inconveniencing
legitimate users or administrators
    + Tracks IP addresses, usernames, and passwords
    + If a login failure uses data matching a past failure, the plugin
      slows down response times.  The more failures, the longer the delay.
      This limits attackers ability to effectively probe your site,
      so they'll give up and go find an easier target.
    + If an account seems breached, the "user" is immediately logged out
      and forced to use WordPress' password reset utility. This prevents
      any damage from being done and verifies the user's identity.  All
      without intervention by an administrator.
    + Can notify the administrator of attacks and breaches
    + Supports IPv6

* Thoroughly examines and enforces password strength.  Includes full
UTF-8 character set support if PHP's `mbstring` extension is enabled.
The tests have caught every password dictionary entry I've tried.
    + Minimum length (customizable)
    + Doesn't match blog info
    + Doesn't match user data
    + Must either have numbers in it or be very long
    + Must either have punctuation, upper and lower case characters or be
      very long
    + Non-sequential codepoints
    + Non-sequential keystrokes (custom sequence files can be added)
    + Not in the password dictionary files you've provided (if any)
    + Decodes "leet" speak
    + The password/phrase is not found by the `dict` dictionary
      program (if available)

* Password aging (optional) (not recommended)
    + Users need to change password every x days (customizable)
    + Grace period for picking a new password (customizable)
    + Remembers old passwords (quantity is customizable)

* Administrators can require all users to change their passwords
    + Done via a flag in each user's database entry
    + No mail is sent, keeping your server off of spam lists

* Logs out idle sessions (optional) (idle time is customizable)

* Maintenance mode (optional)
    + Publicly viewable content remains visible
    + Disables logins by all users, except administrators
    + Logs out existing sessions, except administrators
    + Disables posting of comments
    + Useful for maintenance or emergency reasons
    + This is separate from WordPress' maintenance mode

* Prevents information disclosures from failed logins


= Improvements Over Similar WordPress Plugins =

* Multisite network support
* Takes security seriously so the plugin itself does not open your site
  to SQL, HTML, or header injection vulnerabilities
* Notice-free code means no information disclosures if `display_errors`
  is on and `error_reporting` includes `E_NOTICE`
* Only loads files, actions, and filters needed for enabled options
  and the page's context
* Provides an option to have deactivation remove all of this plugin's
  data from the database
* Uses WordPress' features rather than fighting or overriding them
* No advertising, promotions, or beacons
* Proper internationalization support
* Clean, documented code
* Unit tests covering 100% of the main class


= Securing Your WordPress Site is Important =

You're probably thinking "There's nothing valuable on my website. No one
will bother breaking into it."  What you need to realize is that attackers
are going after your visitors.  They put stealth code on your website
that pushes malware into your readers' browsers.

> According to SophosLabs more than 30,000 websites are infected
> every day and 80% of those infected sites are legitimate.
> Eighty-five percent of all malware, including viruses, worms,
> spyware, adware and Trojans, comes from the web. Today,
> drive-by downloads have become the top web threat.
>
> -- [*Security Threat Report 2012*](http://www.sophos.com/en-us/security-news-trends/reports/security-threat-report/html-08.aspx)

So if your site does get cracked, not only do you waste hours cleaning up,
your reputation gets sullied, security software flags your site as dangerous,
and worst of all, you've inadvertently helped infect the computers of your
clients and friends.  Oh, and if the attack involves malware, that malware
has probably gotten itself into your computer.


= Compatability with Other Plugins =

Some plugins provide similar functionality.  These overlaps can lead to
conflicts during program execution.  Please read the FAQ!


== Installation ==

1. Before installing this plugin, read the FAQ!

1. Download the Login Security Solution zip file from WordPress' plugin
    site: `http://wordpress.org/extend/plugins/login-security-solution/`

1. Unzip the file.

1. Our existing tests are very effective, catching all of the 2 million
    entries in the Dazzlepod password list.  But if you need to block
    specific passwords that my tests miss, this plugin offers the ability
    to provide your own dictionary files.

    Add a file to the `pw_dictionaries` directory and place those passwords
    in it.  One password per line.

    Please be aware that checking the password files is computationally
    expensive.  The following script runs through each of the password
    files and weeds out passwords caught by the other
    tests:

            php utilities/reduce-dictionary-files.php

1. If your website has a large number of non-English-speaking users:

    * See if a keyboard sequence file exists in this plugin's
    `pw_sequences` directory for your target languages.  The following steps
    are for left-to-right languages.  (For right-to-left languages, flip the
    direction of the motions indicated.)
        + Open a text editor and create a file in the `pw_sequences`
            directory
        + Hold down the shift key
        + Press the top left **character** key of the keyboard.
            NOTE: during this entire process, do not press function, control
            or whitespace keys (like tab, enter, delete, arrows, space, etc).
        + Work your way across the top row, pressing each key across the
            row, one by one
        + Press the left-most character key in the second row
        + Go across the second row pressing each key
        + Continue through the entire keyboard in the same manner
        + Let go of the shift key
        + Re-start the process at the top left key of the keyboard and
           work your way through the keyboard, now in lower-case mode
        + Save the file and close the editor
        + Feel free to submit the files to me so others can use it.  See
           the features request section, below.

    * If a translation file for your language does not exist in this
    plugin's `languages` directory, add one.  Read
    http://codex.wordpress.org/I18n_for_WordPress_Developers for
    details.  The files must use UTF-8 encoding.  Send me the file and
    I'll include it in future releases.  See the features request
    section, below.

1. The last step of the new password validation process is checking if
    the password matches an entry in the `dict` program.  See if `dict`
    is installed on your server and consider installing it if not.
    http://en.wikipedia.org/wiki/Dict

1. Upload the `login-security-solution` directory to your
    server's `/wp-content/plugins/` directory

1. Activate the plugin using WordPress' admin interface:
    * Regular sites:  Plugins
    * Sites using multisite networks:  My Sites | Network Admin | Plugins

1. Adjust the settings as desired.  This plugin's settings page can be
    reached via a sub-menu entry under WordPress' "Settings" menu or this
    plugin's entry on WordPress' "Plugins" page.  Sites using WordPress'
    multisite network capability will find the "Settings" and "Plugin"
    menus under "My Sites | Network Admin".

1. Run the "Change All Passwords" process. This is necessary to ensure
    all of your users have strong passwords.  The user interface for
    doing so is accessible via a link in this plugin's entry on
    WordPress' "Plugins" page.

1. Ensure your password strength by changing it.


= Unit Tests =

A thorough set of unit tests are found in the `tests` directory.

The plugin needs to be installed and activated before running the tests.

To execute the tests, `cd` into this plugin's directory and
call `phpunit tests`

Please note that the tests make extensive use of database transactions.
Many tests will be skipped if your `wp_options` and `wp_usermeta` tables
are not using the `InnoDB` storage engine.


= Removal =

1. This plugin offers the ability to remove all of this plugin's settings
    from your database.  Go to WordPress' "Plugins" admin interface and
    click the "Settings" link for this plugin.  In the "Deactivate" entry,
    click the "Yes, delete the damn data" button and save the form.

1. Use WordPress' "Plugins" admin interface to and click the "Deactivate"
    link.

1. Remove the `login-security-solution` directory.


== Frequently Asked Questions ==

= Compatibility with Other Plugins =

* __Better WP Security__:  Their "Enable Login Limits" and "Enable strong
password enforcement" functionality conflict with our features.  The good
news is we provide more robust protection in those areas and the Better WP
Security "Settings" page lets you disable those features in their plugin.
This way you get to enjoy even better security than either plugin alone.

= Where should I report bugs and feature requests? =

Report bugs and submit feature requests by opening a ticket in WordPress'
[plugins Trac website](http://plugins.trac.wordpress.org/report).
Select `login-security-solution` in the "Component" list.

= Where did the "Change All Passwords" interface go? =

A link to the page is found in this plugin's entry in the "Plugins" admin
interface:

* Regular sites:  Plugins
* Sites using multisite networks:  My Sites | Network Admin | Plugins

= Why use slowdowns instead of lockouts? =

The best way to go here is a subject open to debate.  (Hey what isn't?)
I chose the slowdown approach because it keeps legitimate users and
administrators from being inconvenienced.  Plus it provides a quick sand
trap that ties up attackers' resources instead of immediately tipping them
off that the jig is up.

= Won't the slowdowns open my website to Denial of Service (DOS) attacks? =

Yeah, the DOS potential is there.  I mitigated it for the most part by
disconnecting the database link (the most precious resource in most
situations) before sleeping.  But remember, distributed denial of service
attacks are fairly easy to initiate these days.  If someone really wants to
shut down your site, they'll be able to do it without even touching this
plugin's login failure process.

= How do developers generate the POT translation file? =

Get the translation tools from `http://i18n.svn.wordpress.org/tools/trunk/`
then `cd` into that directory and run:

        php makepot.php wp-plugin -d 'error_reporting=E_ALL^E_STRICT' \
            ../login-security-solution \
            ../login-security-solution/languages/login-security-solution.pot


== Changelog ==

= 0.14.0 =
* Add an `.htaccess` file that blocks access to this plugin's directory.

= 0.13.0 =
* Add a script for turning our "Disable Logins" feature on and off from the
command line.

= 0.12.0 =
* Display a notice on top of admin pages when our maintenance mode is enabled.

= 0.11.0 =
* Use POST value for `$user_name` in `login_errors()` because global value
isn't always set.
* Add some more (commented out) log() calls to help users help me help them.

= 0.10.0 =
* Catch $user_ID not being set during "Change All Passwords" submission.
* Add (commented out) log() calls in important spots. Enables users to
help me help them.

= 0.9.0 =
* Fix change that prevented users from logging in after using the password
reset process with an insecure password. Users can now pick a better
password right on the spot.
* Regenerate translation POT file.
* Tested under WordPress 3.3.2 and 3.4RC3, both using regular and multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.8.0 =
* Fix logging user out a second time after WordPress expires cookies.
* It turns out this plugin requires WordPress 3.3, not 3.0.
* Tested under WordPress 3.3.2 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.7.0 =
* The "lost your password" process now validates passwords.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.6.1 =
* Minor wording adjustments.

= 0.6.0 =
* Use `ENT_QUOTES` instead of `ENT_COMPAT` in `htmlspecialchars()` calls
because WordPress mixes and matches the double and single quotes to
delimit attributes.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.5.0 =
* Have multisite network mode use the saved options instead of the defaults.
* Close more HTML injection vectors.  (One would think WordPress' built in
functions would already do this.  Alas...)
* Get the success/error messages to work when saving settings via the
Network Admin page.
* Improve unit tests by ensuring the fail table uses InnoDB.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.4.0 =
* Add multisite network support.
* Keep unit tests from deleting settings.  Note: removes the ability to
run the unit tests without activating the plugin.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.3.0 =
* Use UTF-8 encoding for `htmlspecialchars()` instead of `DB_CHARSET`.
* Tested under WordPress 3.3.1.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.2.1 =
* Ensure all files are in the state I intended.  Needed because
WordPress' plugin site automatically rolls releases.

= 0.2.0 =
* Utilize the $encoding parameter of `htmlspecialchars()` to avoid
problems under PHP 5.4.
* Tested under WordPress 3.3.1.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.1.0 =
* Beta release.

= 0.0.4 =
* Initial import to `plugins.svn.wordpress.org`.

= 0.0.3 =
* Fix mix ups in the code saving the "Change All Passwords" admin UI.
* Adjust IdleTest so it doesn't radically change `wp_users` auto increment.
* Tested under WordPress 3.3.1.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.0.2 =
* Use Unicode character properties to improve portability.
* Stop tests short if not in a WordPress install.
* Skip `dict` test if `dict` not available.
* Skip database tests if transactions are not available.
* Tested under WordPress 3.3.1.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.0.1 =
* Post the code for public review.
* Tested under WordPress 3.3.1.


== To Do ==

* Delete old data in the `fail` table.
* Add some JS/AJAX magic to make users' lives easier by also validating
  passwords on the front end prior to submission.  Patches welcome!


== Bugs and Feature Requests ==

Report bugs and submit feature requests by opening a ticket in WordPress'
[plugins Trac website](http://plugins.trac.wordpress.org/report).
Select `login-security-solution` in the "Component" list.


== Inspiration and References ==

* Password Research
    + [You can never have too many passwords: techniques for evaluating a huge corpus](http://www.cl.cam.ac.uk/~jcb82/doc/B12-IEEESP-evaluating_a_huge_password_corpus.pdf), Joseph Bonneau
    + [Analyzing Password Strength](http://www.cs.ru.nl/bachelorscripties/2010/Martin_Devillers___0437999___Analyzing_password_strength.pdf), Martin Devillers
    + [Consumer Password Worst Practices](http://www.imperva.com/docs/WP_Consumer_Password_Worst_Practices.pdf), Imperva
    + [Preventing Brute Force Attacks on your Web Login](http://www.bryanrite.com/preventing-brute-force-attacks-on-your-web-login/), Bryan Rite
    + [Password Strength](http://xkcd.com/936/), Randall Munroe

* Technical Info
    + [The Extreme UTF-8 Table](http://doc.infosnel.nl/extreme_utf-8.html), infosnel.nl
    + [A Recommendation for IPv6 Address Text Representation](http://tools.ietf.org/html/rfc5952), Seiichi Kawamura and Masanobu Kawashima

* Password Lists
    + [Dazzlepod Password List](http://dazzlepod.com/site_media/txt/passwords.txt), Dazzlepod
    + [Common Passwords](http://www.searchlores.org/commonpass1.htm), Fravia
    + [The Top 500 Worst Passwords of All Time](http://www.whatsmypass.com/the-top-500-worst-passwords-of-all-time), Mark Burnett
