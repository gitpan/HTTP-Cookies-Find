# $rcs = ' $Id: Makefile.PL,v 1.5 2005/07/09 14:38:13 Daddy Exp $ ' ;

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

WriteAll;

print STDERR <<NOTES if ($^O =~ m!win32!i);

Note: Win32::TieRegistry is only needed to find MSIE cookies.

NOTES

1;

__END__

