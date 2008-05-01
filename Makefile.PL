# $Id: Makefile.PL,v 1.9 2008/05/01 22:53:08 Martin Exp $

use inc::Module::Install;

# Name('HTTP-Cookies-Find');
all_from('lib/HTTP/Cookies/Find.pm');
license('perl');

requires('Carp');
requires('Config::IniFiles');
requires('Data::Dumper');
requires('File::HomeDir');
requires('File::Spec');
requires('File::Slurp');
requires('HTTP::Cookies');
requires('HTTP::Cookies::Mozilla');
requires('HTTP::Cookies::Netscape');
build_requires('Test::More');
build_requires('Test::Simple');
requires('User');

if ($^O =~ m!win32!i)
  {
  recommends('HTTP::Cookies::Microsoft');
  recommends('Win32::TieRegistry');
  print STDERR <<'NOTES';

Note: Win32::TieRegistry is only needed to find MSIE cookies;
      you will still be able to find Mozilla cookies if you
      don't have Win32::TieRegistry.

NOTES
  } # if

WriteAll;

1;

__END__

