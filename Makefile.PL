# $rcs = ' $Id: Makefile.PL,v 1.3 2004/10/08 03:26:37 Daddy Exp Daddy $ ' ;

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
recommends('HTTP::Cookies::Microsoft') if ($^O =~ m!win32!i);
recommends('HTTP::Cookies::Mozilla');
recommends('HTTP::Cookies::Netscape');
build_requires('Test::More');
build_requires('Test::Simple');
requires('User');
requires('Win32::TieRegistry') if ($^O =~ m!win32!i);

check_nmake();      # check and download nmake.exe for Win32
&Makefile->write;

print STDERR <<NOTES if ($^O =~ m!win32!i);

Note: Win32::TieRegistry is only needed to find MSIE cookies.

NOTES
