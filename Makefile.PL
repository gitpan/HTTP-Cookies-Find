use inc::Module::Install;

name('HTTP-Cookies-Find');
version_from('lib/HTTP/Cookies/Find.pm');
abstract('Find local cookies file(s) for current user');
author('Martin Thurn <mthurn@cpan.org>');
license('perl');

requires('Config::IniFiles');
requires('File::HomeDir');
requires('File::Spec');
requires('HTTP::Cookies');
requires('HTTP::Cookies::Microsoft');
# requires('HTTP::Cookies::Netscape');  # for future expansion
include_deps('Test::More', 5.004);
build_requires('Test::More');
include_deps('Test::Simple', 5.004);
build_requires('Test::Simple');
requires('User');
requires('Win32::TieRegistry') if ($^O =~ m!win32!i);

check_nmake();      # check and download nmake.exe for Win32
&Makefile->write;
