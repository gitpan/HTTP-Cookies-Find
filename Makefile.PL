# $Id: Makefile.PL,v 1.7 2008/03/06 04:22:03 Daddy Exp $

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
recommends('HTTP::Cookies::Mozilla');
recommends('HTTP::Cookies::Netscape');
build_requires('Test::More');
build_requires('Test::Simple');
requires('User');

if ($^O =~ m!win32!i)
  {
  recommends('HTTP::Cookies::Microsoft');
  requires('Win32::TieRegistry');
  print STDERR <<'NOTES';

Note: Win32::TieRegistry is only needed to find MSIE cookies;
      you will still be able to find Mozilla cookies if you
      don't have Win32::TieRegistry.

NOTES
  } # if

WriteAll;

1;

__END__

