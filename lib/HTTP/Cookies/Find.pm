
# $rcs = ' $Id: Find.pm,v 1.3 2003-12-03 07:34:39-05 kingpin Exp kingpin $ ' ;

package HTTP::Cookies::Find;
use strict;

use Carp;
use Config::IniFiles;
use Data::Dumper;  # for debugging only
use Exporter ();
use File::HomeDir;
use File::Spec::Functions;
use HTTP::Cookies;
use HTTP::Cookies::Netscape;
use User;

use vars qw( @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS );
@ISA         = qw( Exporter HTTP::Cookies );
# Give a hoot don't pollute, do not export more than needed by default
@EXPORT      = qw( );
@EXPORT_OK   = qw( );
%EXPORT_TAGS = ();

my
$VERSION = sprintf("%d.%02d", q$Revision: 1.3 $ =~ /(\d+)\.(\d+)/o);

=head1 NAME

HTTP::Cookies::Find - Locate cookies for the current user on the local machine.

=head1 SYNOPSIS

  use HTTP::Cookies::Find;
  my $oCookies = HTTP::Cookies::Find->new('domain.com');
  # $oCookies is a subclass of HTTP::Cookies

  # Call in array context to find cookies from multiple
  # browsers/versions:
  my @aoCookies = HTTP::Cookies::Find->new('domain.com');
  @aoCookies is an array of HTTP::Cookies objects

=head1 DESCRIPTION

Note that the returned object contains a read-only copy of the found
cookies.

=head1 USAGE



=cut

############################################# main pod documentation end ##

use constant DEBUG_NEW => 0;

# We use global variables so that the callback function can see them:
use vars qw( $sUser $sHostGlobal $oReal );

sub new
  {
  my $class = shift;
  $sHostGlobal = lc shift || '';
  my $oDummy;
  my @aoRet;
  if ($^O =~ m!win32!i)
    {
    # We use a fake while loop so we can abort the MSIE process at any
    # time (without using goto):
 WIN32_MSIE:
    while (1)
      {
      # Massage the hostname in an attempt to make it match MS' highlevel
      # naming scheme:
      my $sHost = $sHostGlobal;
      $sHost =~ s!\.(com|edu|gov|net|org)\Z!!;  # delete USA domain
      $sHost =~ s!\.[a-z][a-z]\.[a-z][a-z]\Z!!;  # delete intl domain
      # We only look at cookies for the logged-in user:
      $sUser = lc User->Login;
      print STDERR " + Finding cookies for user $sUser...\n" if DEBUG_NEW;
      my ($sDir, %hsRegistry);
      eval q{use HTTP::Cookies::Microsoft};
      eval q{use Win32::TieRegistry(
                                  Delimiter => '/',
                                  TiedHash => \%hsRegistry,
                                 )};
      # Make sure the eval succeeded?
      eval { $sDir = $hsRegistry{"CUser/Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders/Cookies"} || '' };
      if ($@)
        {
        # carp qq{ --- eval of assignment from registry failed: $@\n};
        last WIN32_MSIE;
        } # if
      if ($sDir eq '')
        {
        carp qq{ --- can not find registry entry for MSIE cookies\n};
        last WIN32_MSIE;
        } # if
      unless (-d $sDir)
        {
        carp qq{ --- registry entry for MSIE cookies is $sDir but that directory does not exist.\n};
        last WIN32_MSIE;
        } # unless
      # This will be the object we return:
      my $oRealMSIE = HTTP::Cookies::Microsoft->new;
      $oReal = $oRealMSIE;
      unless (ref $oReal)
        {
        carp qq{ --- can not create an HTTP::Cookies::Microsoft object.\n};
        last WIN32_MSIE;
        } # unless
      # This is a dummy object that we use to find the appropriate
      # cookies:
      $oDummy = HTTP::Cookies::Microsoft->new(
                                              File => "$sDir\\index.dat",
                                              'delayload' => 1,
                                             );
      $oDummy->scan(\&callback_msie) if ref($oDummy);
      last WIN32_MSIE;
      } # end of WIN32_MSIE while block
    # At this point, $oReal contains MSIE cookies (or undef).
    if (ref($oReal))
      {
      return $oReal if ! wantarray;
      push @aoRet, $oReal;
      } # if found MSIE cookies
    # If wantarray, or the MSIE cookie search failed, go on and look
    # for Netscape cookies:
 WIN32_NETSCAPE:
      {
      $oReal = undef;
      my $sDirWin = $ENV{WINDIR};
      my $sFnameWinIni = catfile($sDirWin, 'win.ini');
      if (! -f $sFnameWinIni)
        {
        carp qq{ --- Windows ini file $sFnameWinIni does not exist\n};
        last WIN32_NETSCAPE;
        } # if
      my $oIniWin = new Config::IniFiles(
                                         -file => $sFnameWinIni,
                                        );
      if (! ref($oIniWin))
        {
        carp qq{ --- can not parse $sFnameWinIni\n};
        last WIN32_NETSCAPE;
        } # if
      my $sFnameNSIni = $oIniWin->val('Netscape', 'ini');
      if (! -f $sFnameNSIni)
        {
        carp qq{ --- Netscape ini file $sFnameNSIni does not exist\n};
        last WIN32_NETSCAPE;
        } # if
      my $oIniNS = Config::IniFiles->new(
                                         -file => $sFnameNSIni,
                                        );
      if (! ref($oIniNS))
        {
        carp qq{ --- can not parse $sFnameNSIni\n};
        last WIN32_NETSCAPE;
        } # if
      my $sFnameCookies = $oIniNS->val('Cookies', 'Cookie File');
      if (! -f $sFnameCookies)
        {
        carp qq{ --- Netscape cookies file $sFnameCookies does not exist\n};
        last WIN32_NETSCAPE;
        } # if
      # This will be the object we return:
      my $oRealNS = HTTP::Cookies::Netscape->new;
      $oReal = $oRealNS;
      unless (ref $oReal)
        {
        carp qq{ --- can not create an empty HTTP::Cookies::Netscape object.\n};
        last WIN32_MSIE;
        } # unless
      # This is a dummy object that we use to find the appropriate
      # cookies:
      $oDummy = HTTP::Cookies::Netscape->new(
                                             File => $sFnameCookies,
                                             'delayload' => 1,
                                            );
      $oDummy->scan(\&callback_mozilla) if ref($oDummy);
      last WIN32_NETSCAPE;
      } # end of WIN32_NETSCAPE block
    # At this point, $oReal contains Netscape cookies (or undef).
    if (ref($oReal))
      {
      return $oReal if ! wantarray;
      push @aoRet, $oReal;
      } # if found MSIE cookies
    # No more places to look, fall through and return what we've
    # found.
    } # if MSWin32
  elsif ($^O =~ m!solaris!i)
    {
    ;
 UNIX_NETSCAPE4:
      {
      my $sFname = catfile(home(), '.netscape', 'cookies');
      print STDERR " + try $sFname...\n" if DEBUG_NEW;
      if (! -f $sFname)
        {
        # carp qq{ --- can not find Netscape4 cookie file at $sFname\n};
        last UNIX_NETSCAPE4;
        # Fall through and try Netscape7.
        } # if
      $oDummy = HTTP::Cookies::Netscape->new(file => $sFname);
      if (! ref($oDummy))
        {
        carp qq{ --- can not create HTTP::Cookies::Netscape object\n};
        last UNIX_NETSCAPE4;
        } # if
      # This will be the object we return:
      my $oRealNS4 = HTTP::Cookies::Netscape->new;
      $oReal = $oRealNS4;
      if (! ref($oReal))
        {
        carp qq{ --- can not create empty HTTP::Cookies::Netscape object\n};
        last UNIX_NETSCAPE4;
        } # if
      $oDummy->scan(\&callback_mozilla) if ref($oDummy);
      push @aoRet, $oReal;
      last UNIX_NETSCAPE4;
      } # end of UNIX_NETSCAPE4 block
    ;
 UNIX_NETSCAPE7:
      {
      ;
      } # end of UNIX_NETSCAPE7 block
    ;
    } # if solaris
  else
    {
    # Future expansion: implement Netscape / other OS conbinations
    }
  return wantarray ? @aoRet : $oReal;
  } # new


sub callback_msie
  {
  my ($version,
      $key, $val,
      $path, $domain, $port, $path_spec,
      $secure, $expires, $discard, $hash) = @_;
  # All we care about at this level is the filename, which is in the
  # $val slot:
  print STDERR " + consider cookie, val==$val==\n" if (1 < DEBUG_NEW);
  return unless ($val =~ m!\@.*$sHostGlobal!);
  print STDERR " +   matches host ($sHostGlobal)\n" if DEBUG_NEW;
  return unless ($val =~ m!$sUser\@!);
  print STDERR " +   matches user ($sUser)\n" if DEBUG_NEW;
  # This cookie file matches the user and host.  Add it to the cookies
  # we'll keep:
  $oReal->load_cookie($val);
  } # callback_msie

sub callback_mozilla
  {
  # print STDERR " + callback got a cookie: ", Dumper(\@_);
  # return;
  # my ($version,
  #     $key, $val,
  #     $path, $domain, $port, $path_spec,
  #     $secure, $expires, $discard, $hash) = @_;
  my $sDomain = $_[4];
  print STDERR " +   consider cookie from domain ($sDomain), want host ($sHostGlobal)...\n" if DEBUG_NEW;
  return if (($sHostGlobal ne '') && ($sDomain !~ m!$sHostGlobal!));
  print STDERR " +     domain ($sDomain) matches host ($sHostGlobal)\n" if DEBUG_NEW;
  $oReal->set_cookie(@_);
  } # callback_mozilla

=head1 BUGS

Please notify the author if you find any.

=head1 AUTHOR

Martin Thurn E<lt>mthurn@cpan.orgE<gt>

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

HTTP::Cookies, HTTP::Cookies::Microsoft, HTTP::Cookies::Netscape

=cut

1;

__END__

