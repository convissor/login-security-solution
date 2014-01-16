=== Login Security Solution ===
Contributors: convissor
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=danielc%40analysisandsolutions%2ecom&lc=US&item_name=Donate%3a%20Login%20Security%20Solution&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted
Tags: login, password, passwords, strength, strong, strong passwords, password strength, idle, timeout, maintenance, security, attack, hack, lock, lockdown, ban, brute force, brute, force, authentication, xml-rpc, auth, cookie, users
Requires at least: 3.3
Tested up to: 3.6beta3
Stable tag: trunk

Security against brute force attacks by tracking IP, name, password; requiring very strong passwords. Idle timeout. Maintenance mode lockdown.


== Description ==

A simple way to lock down login security for multisite and regular
WordPress installations.

* Blocks brute force and dictionary attacks without inconveniencing
legitimate users or administrators
    + Tracks IP addresses, usernames, and passwords
    + Monitors logins made by form submissions, XML-RPC requests and
      auth cookies
    + If a login failure uses data matching a past failure, the plugin
      slows down response times.  The more failures, the longer the delay.
      This limits attackers ability to effectively probe your site,
      so they'll give up and go find an easier target.
    + If an account seems breached, the "user" is immediately logged out
      and forced to use WordPress' password reset utility.  This prevents
      any damage from being done and verifies the user's identity.  But
      if the user is coming in from an IP address they have used in the
      past, an email is sent to the user making sure it was them logging in.
      All without intervention by an administrator.
    + Can notify the administrator of attacks and breaches
    + Supports IPv6

* Thoroughly examines and enforces password strength.  Includes full
UTF-8 character set support if PHP's `mbstring` extension is enabled.
The tests have caught every password dictionary entry I've tried.
    + Minimum length (customizable)
    + Doesn't match blog info
    + Doesn't match user data
    + Must either have numbers, punctuation, upper and lower case characters
      or be very long.  Note: alphabets with only one case (e.g. Arabic,
      Hebrew, etc.) are automatically exempted from the upper/lower case
      requirement.
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
* Monitors authentication cookies for bad user names and hashes
* Tracks logins from XML-RPC requests
* Adjusts WordPress' password policy user interfaces
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
* Internationalized unit tests

For reference, the similar plugins include:

* [6Scan Security](http://wordpress.org/extend/plugins/6scan-protection/)
* [Better WP Security](http://wordpress.org/extend/plugins/better-wp-security/)
* [Enforce Strong Password](http://wordpress.org/extend/plugins/enforce-strong-password/)
* [Force Strong Passwords](http://wordpress.org/extend/plugins/force-strong-passwords/)
* [Limit Login Attempts](http://wordpress.org/extend/plugins/limit-login-attempts/)
* [Login Lock](http://wordpress.org/extend/plugins/login-lock/)
* [Login LockDown](http://wordpress.org/extend/plugins/login-lockdown/)
* [PMC Lockdown](http://wordpress.org/extend/plugins/pmc-lockdown/)
* [Simple Login Lockdown](http://wordpress.org/extend/plugins/simple-login-lockdown/)
* [Wordfence Security](http://wordpress.org/extend/plugins/wordfence/)
* [WP Login Security](http://wordpress.org/extend/plugins/wp-login-security/)
* [WP Login Security 2](http://wordpress.org/extend/plugins/wp-login-security-2/)


= Compatibility with Other Plugins =

Some plugins provide similar functionality.  These overlaps can lead to
conflicts during program execution.  Please read the FAQ!


= Translations =

* Deutsche, Deutschland (German, Germany) (de_DE) by Christian Foellmann
* Français, français (French, France) (fr_FR) by [mermouy](http://wordpress.org/support/profile/mermouy) and and Fx Bénard
* Nederlands, Nederland (Dutch, Netherlands) (nl_NL) by Friso van Wieringen
* Português, Brasil (Portugese, Brazil) (pt_BR) by Valdir Trombini


= Source Code, Bugs, and Feature Requests =

Development of this plugin happens on
[GitHub](https://github.com/convissor/login-security-solution).
Please submit
[bug and feature requests](https://github.com/convissor/login-security-solution/issues),
[pull requests](https://github.com/convissor/login-security-solution/pulls),
[wiki entries](https://github.com/convissor/login-security-solution/wiki)
there.
Releases are then squashed and pushed to WordPress'
[Plugins SVN repository](http://plugins.svn.wordpress.org/login-security-solution/).
This division is necessary due having being chastised that "the Plugins SVN
repository is a release system, not a development system."

Old tickets are in the [Plugins Trac](https://plugins.trac.wordpress.org/query?status=assigned&status=closed&status=new&status=reopened&component=login-security-solution&col=id&col=summary&col=status&col=owner&col=type&col=priority&col=component&desc=1&order=id).


= Strong, Unique Passwords Are Important =

Yeah, creating, storing/remembering, and using a __different__, __strong__
password for each site you use is a hassle.  _But it is absolutely
necessary._

Password lists get stolen on a regular basis from big name sites (like
Linkedin for example!).  Criminals then have unlimited time to decode the
passwords.  In general, 50% of those passwords are so weak they get figured
out in a matter of seconds.  Plus there are computers on the Internet
dedicated to pounding the sites with login attempts, hoping to get lucky.

Many people use the same password for multiple sites.  Once an attacker
figures out your password on one site, they'll try it on your accounts at
other sites.  It gets ugly very fast.

But don't despair!  There are good, free tools that make doing the right
thing a piece of cake.  For example: [KeePassX](http://www.keepassx.org/),
[KeePass](http://keepass.info/),
or [1Password](https://agilebits.com/onepassword)


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


== Installation ==

1. Before installing this plugin, read the FAQ!

1. If your WP install is behind a proxy or load balancer, please be aware
    that this plugin uses the `REMOTE_ADDR` provided by the web server
    (as does WordPress' new comment functionality and the Akismet plugin).
    If you want our brute force tracking to work, we advise adjusting your
    `wp-config.php` file to manually set the `REMOTE_ADDR` to a data
    source appropriate for your environment.  For example:

            $_SERVER['REMOTE_ADDR'] = preg_replace('/^([^,]+).*$/', '\1',
                $_SERVER['HTTP_X_FORWARDED_FOR']);

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

Translations can be tested by changing the `WPLANG` value in `wp-config.php`.

Please note that the tests make extensive use of database transactions.
Many tests will be skipped if your `wp_options` and `wp_usermeta` tables
are not using the `InnoDB` storage engine.


= Removal =

1. This plugin offers the ability to remove all of this plugin's settings
    from your database.  Go to WordPress' "Plugins" admin interface and
    click the "Settings" link for this plugin.  In the "Deactivate" entry,
    click the "Yes, delete the damn data" button and save the form.

1. Use WordPress' "Plugins" admin interface to click the "Deactivate" link

1. Remove the `login-security-solution` directory from the server

In the event you didn't pick the "Yes, delete the damn data" option or
you manually deleted the plugin, you can get rid of the settings by running
three queries.  These  queries are exapmles, using the default table name
prefix of, `wp_`.  If you have changed your database prefix, adjust the
queries accordingly.

        DROP TABLE wp_login_security_solution_fail;

        DELETE FROM wp_options WHERE option_name LIKE 'login-security-solution%';

        DELETE FROM wp_usermeta WHERE meta_key LIKE 'login-security-solution%';

== Frequently Asked Questions ==

= Compatibility with Other Plugins =

* __Better WP Security__:  Their "Enable Login Limits" and "Enable strong
password enforcement" functionality conflict with our features.  The good
news is we provide more robust protection in those areas and the Better WP
Security "Settings" page lets you disable those features in their plugin.
This way you get to enjoy even better security than either plugin alone.

= Why should I pick a user name other than "admin"? =

The WordPress installation process (currently) defaults to having the
main administrator's user's name be "admin."  Many people don't change it.
Attackers know this, so now all they need to do to get into such sites is
guess the password.

In addition, if you try to log in while your site is being attacked, this
plugin will send you through the password reset process in order to verify
your identity.  While not the end of the world, it's inconvenient.

= Where did the "Change All Passwords" interface go? =

A link to the page is found in this plugin's entry in the "Plugins" admin
interface:

* Regular sites:  Plugins
* Sites using multisite networks:  My Sites | Network Admin | Plugins

= I just got hit with 500 failed logins! Why isn't this plugin working?!? =

Let's turn the question around: "How long did it take to get in those 500
hits?"  Chances are it took hours.  (Six hours if they're attacking with one
thread, 2 hours if they're coming at you with three threads, etc.)  If this
plugin wasn't working, they'd have pulled it off under a minute.  Similarly,
without the slowed responses this plugin provides, an attacker given six
hours against your site could probably get in over 170,000 hits.

Anyway, my real question for you is "Did they get in?"  I'll bet not.  The
strong passwords this plugin requires from your users lowers the chances of
someone breaking in to just about zero.

And even if they _do_ get lucky and figure out a password, Login Security
Solution realizes they're miscreants and kicks them out.

= Will you provide lock outs / blocks in addition to slow downs? =

If you look at it the right way, Login Security Solution provides lockouts
(where "lockout" means "denies access" to attackers.)  Below is a comparison
of the attack handling logic used by Limit Login Attempts and Login Security
Solution.

__Limit Login Attempts__

* _Invalid or Valid Credentials by Attacker or Actual User_

    1. Process authentication request (check IP address)
    1. Error message: "Too many failed login attempts." (ACCESS DENIED.)

Note, this approach means an actual user can be denied access for 12 hours after making 4 mistakes.


__Login Security Solution__

* _Invalid Credentials by Attacker or Actual User_

    1. Process authentication request (check IP, user name, and password)
    1. Slow down the response
    1. Error message: "Incorrect username or password." (ACCESS DENIED.)

* _Valid Credentials by Attacker_

    1. Process authentication request (check IP, user name, and password)
    1. Slow down the response
    1. Set force password change flag for user
    1. Error message: "Your password must be reset. Please submit this form to reset it." (ACCESS DENIED.)

* _Valid Credentials by Actual User_

    1. Process authentication request (check IP, user name, and password)
    1. (If user is coming from their verified IP address, let them in, END)
    1. Slow down the response
    1. Error message: "Your password must be reset. Please submit this form to reset it." (ACCESS DENIED.)
    1. On subsequent request... user verifies their identity via password reset process
    1. User's IP address is added to their verified IP list for future reference

So both plugins deny access to attackers. But Login Security Solution has
the bonuses of letting legitimate users log in and slowing the attacks down.
Plus LSS monitors user names, passwords, and IP's for attacks, while all of
the other plugins just watch the IP address.

= Won't the slowdowns open my website to Denial of Service (DOS) attacks? =

Yeah, the DOS potential is there.  I mitigated it for the most part by
disconnecting the database link (the most precious resource in most
situations) before sleeping.  But remember, distributed denial of service
attacks are fairly easy to initiate these days.  If someone really wants to
shut down your site, they'll be able to do it without even touching this
plugin's login failure process.

= Where should I report bugs and feature requests? =

Development of this plugin happens on
[GitHub](https://github.com/convissor/login-security-solution).
Please submit
[bug and feature requests](https://github.com/convissor/login-security-solution/issues),
[pull requests](https://github.com/convissor/login-security-solution/pulls),
[wiki entries](https://github.com/convissor/login-security-solution/wiki)
on our GitHub.

= Information for Translators =

1. __Do not__ commit the `.mo` files!  They get created as part of the
    release process.
1. Translation commits and pull requests should __only__ touch the `.po`
    file.  If you have other changes you wish to see made, please do so
    via separate commits in separate pull requests.
1. When translating a new feature, please make that one commit.  If other
    parts of the translation need updating, please make them in a separate
    commit.
1. Please don't change formatting inside the `.po` file
1. __Run `git diff` before all commits.__  Ensure only expected changes
    are being made.
1. Do not translate items that have a comment above them saying
    `Translation from WordPress.`  Those phrases are already translated
    in Wordporess' core.  Leaving them untranslated here ensures
    consistency with the rest of WordPress.

= Translation Information for Developers =

* To update the `.pot` file:

    1. WordPress' `makepot` utility directory should be in the same directory
        as the `login-security-solution` directory.  If you don't have this
        setup, here's what to do:
        * cd into the directory above this one.
        * `svn checkout http://i18n.svn.wordpress.org/tools/trunk/ makepot`
        * So, now you'll have:

                parent dir
                    |- login-security-solution/
                    |- makepot/

    1. `cd login-security-solution/languages`
    1. `./makepot.sh`

* Then, bringing the `.po` files up to date is as easy as:

    1. `./updatepos.sh`

* Finally, to update the `.mo` files for testing or release:

    1. `./makemos.sh`


== Changelog ==

= 0.43.0 (2014-01-16) =
* By popular demand, notification emails now include the full IP address.

= 0.42.0 (2013-07-06) =
* Have Maintenence Mode messaging say who turned it on and how to turn it off.
* Added pw_sequence for German T1 keyboard layout. (cfoellmann)

= 0.41.0 (2013-06-26) =
* Fix "authenticate filter not called" when auth process lacks a user name.

= 0.40.0 (2013-06-22) =
* Track the age of verified IP's and use that to prevent users being locked
out by "attacks" from one's own IP address.
* Unit tests pass using PHP 5.3.27-dev, 5.4.17-dev, 5.5.0-dev
* Tested under WordPress 3.4.2, 3.5.2 and 3.6beta4 using regular and multisite.

= 0.39.0 (2013-05-29) =
* Enforce password history during password reset process.

= 0.38.0 (2013-05-27) =
* Mention that the password force change process does not touch the admin
that presses the button.
* Remove HTML special characters when using WP's `blogname` setting.
* Unit tests pass using PHP 5.3.27-dev, 5.4.17-dev, 5.5.0-dev
* Tested under WordPress 3.5.1 and 3.6beta3 using regular and multisite.

= 0.37.0 (2013-04-29) =
* Monitor login attempts from XML-RPC requests.
* Fix "te ernstig te" in the Dutch translation (thanks fwieringen@github).

= 0.36.0 (2013-04-13) =
* Have the password reset page say why a password isn't strong enough.
* Add Dutch translation.

= 0.35.0 (2013-02-22) =
* Don't track cookie failures if name or hash is empty.
* Add German translation.
* Update French translation.
* Documentation improvements.

= 0.34.0 (2012-10-21) =
* Have `login_errors` filter check `$wp_error` also, not just `$errors.`
* Skip `exec()` calls if `safe_mode` is on.
* Unit tests pass using WordPress 3.5 RC2 under PHP 5.4.5-dev and 5.3.19-dev.

= 0.33.0 (2012-10-18) =
* Add text to failure alerts saying the attacker will be denied access.
* Have failure alerts say there won't be further emails.

= 0.32.0 (2012-10-04) =
* SIGNIFICANT CHANGE:  Reduce the number of emails sent to administrators:
add the "Multiple Failure Notifications" setting and make the default "No."
* Remove the (superfluous) "If it WAS YOU..." part of the user notification
emails.
* Use `wp_cache_flush()` in unit tests, `wp_cache_reset()` deprecated in 3.5.
* Unit tests pass using PHP 5.4.5-dev, 5.3.16-dev.
* Tested under WordPress 3.4.2 and 3.5beta1 using regular and multisite.

= 0.31.0 (2012-09-25) =
* Have breach notification emails detail the exact situation depending on
the system's settings.

= 0.30.0 (2012-09-17) =
* Translate "Confirm" and "No thanks" phrases on the settings screen.
* Adjust readme to indicate that development has moved to
[GitHub](https://github.com/convissor/login-security-solution).

= 0.29.0 (2012-09-17) =
* Adjust formatting of the `CREATE TABLE` statement in `activate()` to prevent
WordPress' `dbDelta()` from creating duplicate keys each time the plugin is
activated.

= 0.28.1 (2012-09-15) =
* Update `.mo` translation files.

= 0.28.0 (2012-09-15) =
* Remove loophole:  slow down successful logins as well (for non-verified
IP addresses).  Keeps attackers from using timeouts to skip our delayed
responses to failed login attempts.
* Reduce false positives for breach notifications and password resets:
    - Allow users through without incident if the user's Network IP failure
      count is less than the "Breach Email Confirm" setting.  The old
      behavior was to do so only if the Network IP failure count was 0.
    - Add user's current IP to their verified IP list whenever they save
      their profile page, not just when they change their password.
    - Fix when user notifications are sent.  Do so if the IP address is
      NOT verified instead of if the IP address IS verified.  Duh.
    - Don't notify administrators of a successful login if the user is
      coming in from a verified IP address.
    - Change subject line of user notification emails to differentiate them
      from emails sent to admins.
    - Reword user notification email and have it explain how to reduce
      future hassles.
* Remove URIs from user notification email to avoid phishing imitations.
* Add pt_BR translation.  Thanks to Valdir Trombini.
* Put plugin version number in admin notification emails.
* Update the fr_FR translation: update password policy, add settings page.
* Put Unicode flag on the two preg calls that didn't have it.  Fixes
password parsing problem on Windows.
* Add date to log() messages.
* Unit tests pass using PHP 5.4.5-dev, 5.3.16-dev, and 5.2.18-dev.
* Tested under WordPress 3.4.2 using regular and multisite.
* Also tested on Windows 7 using WordPress 3.4.1 and PHP 5.4.5 with mbstring
enabled and disabled.

= 0.27.0 (2012-09-04) =
* Remove the password policy explanation link added in 0.26.0.

= 0.26.0 (2012-09-01) =
* Put a link in the password policy to an explanation of why it's necessary.

= 0.25.0 (2012-08-30) =
* Load text domain for password policy on password reset page.
* Have password policy mention that it can't contain words related to
the user or the website.

= 0.24.0 (2012-08-29) =
* Keep the password strength indicator from being enabled.
* Narrow down when the password policy text filter is enabled.

= 0.23.0 (2012-08-24) =
* Split user and site info into components before comparing them.
* Increase minimum password length to 10 characters.

= 0.22.0 (2012-08-17) =
* Track a given IP, user name, password combination only once.
* Prevent "not a valid MySQL-Link resource" on auth cookie failure.
* Increase default value of login_fail_notify from 20 to 50.
* Add partial French translation.  Settings page needs doing.  Thanks
[mermouy](http://wordpress.org/support/profile/mermouy)!

= 0.21.0 (2012-08-07) =
* Fix is_pw_outside_ascii() to permit spaces.
* In multisite mode, send notifications to network admin, not blog admin.
* Add "Notifications To" setting for admins to specify the email addresses
the failure and breach notifications get sent to. (Request #1560)
* Clarify that the Change All Passwords link just goes to the UI.
* Get all unit tests to pass when mbstring isn't enabled.
* Internationalize the unit tests.
* Rename admin.inc to admin.php.
* Rename temporary files holding actual test results. (Bug #1552 redux)
* Unit tests pass using PHP 5.4.5-dev, 5.3.16-dev, and 5.2.18-dev.
* Tested under WordPress 3.4.1 using regular and multisite.
* Also tested on Windows 7 using PHP 5.4.5 and WordPress 3.4.1.

= 0.20.2 (2012-07-12) =
* Ugh, update the translation pot file.

= 0.20.1 (2012-07-12) =
* Add "numbers" to the password policy text.

= 0.20.0 (2012-07-12) =
* Replace WP's password policy text with our own.

= 0.19.0 (2012-07-11) =
* Remove inadvertent log call added in 0.17.0.

= 0.18.0 (2012-07-11) =
* Keep legit user from having to repeatedly reset pw during active attacks
against their user name.

= 0.17.0 (2012-07-09) =
* Fix network IP query in get_login_fail(). (Bug #1553,
[deanmarktaylor](http://wordpress.org/support/profile/deanmarktaylor))
* Rename files holding expected test results. (Bug #1552,
[deanmarktaylor](http://wordpress.org/support/profile/deanmarktaylor))

= 0.16.0 (2012-07-08) =
* Have shell script gracefully handle value already being the desired value.

= 0.15.0 (2012-07-06) =
* Log auth cookie failures too.
* Clean up sleep logic. (Bug #1549,
[deanmarktaylor](http://wordpress.org/support/profile/deanmarktaylor))

= 0.14.0 (2012-07-05) =
* Fix emails being mistakenly sent in multisite mode that say "There have
been at least 0 failed attempts to log in".  (Bug #1548,
[deanmarktaylor](http://wordpress.org/support/profile/deanmarktaylor))
* Add an `.htaccess` file that blocks access to this plugin's directory.

= 0.13.0 (2012-07-01) =
* Add a script for turning our "Disable Logins" feature on and off from the
command line.

= 0.12.0 (2012-06-30) =
* Display a notice on top of admin pages when our maintenance mode is enabled.

= 0.11.0 (2012-06-28) =
* Use `POST` value for `$user_name` in `login_errors()` because global value
isn't always set.
* Add some more (commented out) log() calls to help users help me help them.

= 0.10.0 (2012-06-16) =
* Catch $user_ID not being set during "Change All Passwords" submission.
* Add (commented out) log() calls in important spots. Enables users to
help me help them.

= 0.9.0 (2012-06-16) =
* Fix change that prevented users from logging in after using the password
reset process with an insecure password. Users can now pick a better
password right on the spot.
* Regenerate translation POT file.
* Tested under WordPress 3.3.2 and 3.4RC3, both using regular and multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.8.0 (2012-04-29) =
* Fix logging user out a second time after WordPress expires cookies.
* It turns out this plugin requires WordPress 3.3, not 3.0.
* Tested under WordPress 3.3.2 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.7.0 (2012-04-25) =
* The "lost your password" process now validates passwords.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.6.1 (2012-04-19) =
* Minor wording adjustments.

= 0.6.0 (2012-04-18) =
* Use `ENT_QUOTES` instead of `ENT_COMPAT` in `htmlspecialchars()` calls
because WordPress mixes and matches the double and single quotes to
delimit attributes.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.5.0 (2012-04-18) =
* Have multisite network mode use the saved options instead of the defaults.
* Close more HTML injection vectors.  (One would think WordPress' built in
functions would already do this.  Alas...)
* Get the success/error messages to work when saving settings via the
Network Admin page.
* Improve unit tests by ensuring the fail table uses InnoDB.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.4.0 (2012-04-17) =
* Add multisite network support.
* Keep unit tests from deleting settings.  Note: removes the ability to
run the unit tests without activating the plugin.
* Tested under WordPress 3.3.1 regular and 3.4beta2 multisite.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.3.0 (2012-04-04) =
* Use UTF-8 encoding for `htmlspecialchars()` instead of `DB_CHARSET`.
* Tested under WordPress 3.3.1.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.2.1 (2012-04-03) =
* Ensure all files are in the state I intended.  Needed because
WordPress' plugin site automatically rolls releases.

= 0.2.0 (2012-04-03) =
* Utilize the $encoding parameter of `htmlspecialchars()` to avoid
problems under PHP 5.4.
* Tested under WordPress 3.3.1.
* Unit tests pass using PHP 5.4.0RC8-dev, 5.3.11-dev, and 5.2.18-dev.

= 0.1.0 (2012-03-26) =
* Beta release.

= 0.0.4 (2012-03-22) =
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

= 0.0.1 (2012-03-19) =
* Post the code for public review.
* Tested under WordPress 3.3.1.


== Other Notes ==

= Inspiration and References =

* Password Research
    + [Why passwords have never been weaker -- and crackers have never been stronger](http://arstechnica.com/security/2012/08/passwords-under-assault/), Dan Goodin
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

= To Do =

* Delete old data in the `fail` table.
* Provide a user interface to the `fail` table.
