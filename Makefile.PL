use inc::Module::Install;

name('HTTP-Cookies-Find');
version_from('lib/HTTP/Cookies/Find.pm');
abstract('Find local cookies file(s) for current user');
author('Martin Thurn <mthurn@cpan.org>');
license('perl');

requires('Config::IniFiles');
requires('File::HomeDir');
requires('File::Spec');
requires('File::Slurp');
requires('HTTP::Cookies');
requires('HTTP::Cookies::Microsoft');
requires('HTTP::Cookies::Mozilla');
requires('HTTP::Cookies::Netscape');
build_requires('Test::More');
build_requires('Test::Simple');
requires('User');
requires('Win32::TieRegistry') if ($^O =~ m!win32!i);

check_nmake();      # check and download nmake.exe for Win32
&Makefile->write;

print STDERR <<NOTES;

Notes:
HTTP::Cookies::Microsoft is only needed on Windows.
HTTP::Cookies::Mozilla is only needed on Solaris and Linux.
Win32::TieRegistry is only needed to find MSIE cookies on Windows.

NOTES
