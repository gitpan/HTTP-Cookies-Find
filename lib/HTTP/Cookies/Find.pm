
# $rcs = ' $Id: Find.pm,v 1.408 2005/12/25 00:03:31 Daddy Exp $ ' ;

package HTTP::Cookies::Find;

use Carp;
use Config::IniFiles;
use Data::Dumper;  # for debugging only
use Exporter ();
use File::HomeDir;
use File::Spec::Functions;
use File::Slurp;
use HTTP::Cookies;
# use HTTP::Cookies::Mozilla;
use HTTP::Cookies::Netscape;
use User;

use strict;

use vars qw( @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS );
@ISA         = qw( Exporter HTTP::Cookies );
# Give a hoot don't pollute, do not export more than needed by default
@EXPORT      = qw( );
@EXPORT_OK   = qw( );
%EXPORT_TAGS = ();

my
$VERSION = do { my @r = (q$Revision: 1.408 $ =~ /\d+/g); sprintf "%d."."%03d" x $#r, @r };

=head1 NAME

HTTP::Cookies::Find - Locate cookies for the current user on the local machine.

=head1 SYNOPSIS

  use HTTP::Cookies::Find;
  my $oCookies = HTTP::Cookies::Find->new('domain.com');
  my @asMsg = HTTP::Cookies::Find::errors;
  # Now $oCookies is a subclass of HTTP::Cookies
  # and @asMsg is an array of error messages

  # Call in array context to find cookies from multiple
  # browsers/versions:
  my @aoCookies = HTTP::Cookies::Find->new('domain.com');
  # Now @aoCookies is an array of HTTP::Cookies objects

=head1 DESCRIPTION

Looks in various normal places for HTTP cookie files.
Returns an object (or array of objects) of type HTTP::Cookies::[vendor].
The returned object(s) are not tied to the cookie files;
the returned object(s) contain read-only copies of the found
cookies.
If no argument is given to new(), the returned object(s) contain read-only copies of ALL cookies.
If an argument is given to new(), the returned object(s) contain read-only copies of only those cookies whose hostname "matches" the argument.
Here "matches" means case-insensitive pattern match;
you can pass a qr{} regexp as well as a plain string for matching.

=head1 USAGE



=cut

############################################# main pod documentation end ##

use constant DEBUG_NEW => 0;
use constant DEBUG_GET => 0;

# We use global variables so that the callback function can see them:
use vars qw( $sUser $sHostGlobal $oReal );

my @asError;

sub _add_error
  {
  push @asError, shift;
  } # _add_error

sub errors
  {
  return @asError;
  } # errors

sub new
  {
  my $class = shift;
  $sHostGlobal = shift || '';
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
      print STDERR " + Finding cookies for user $sUser with host matching ($sHost)...\n" if DEBUG_NEW;
      my ($sDir, %hsRegistry);
      eval q{require HTTP::Cookies::Microsoft};
      if ($@)
        {
        _add_error qq{ --- can not require HTTP::Cookies::Microsoft: $@\n};
        last WIN32_MSIE;
        } # if
      eval q{use Win32::TieRegistry(
                                    Delimiter => '/',
                                    TiedHash => \%hsRegistry,
                                   )};
      if ($@)
        {
        _add_error qq{ --- can not use Win32::TieRegistry: $@\n};
        last WIN32_MSIE;
        } # if
      $sDir = $hsRegistry{"CUser/Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders/Cookies"} || '';
      if ($sDir eq '')
        {
        _add_error qq{ --- can not find registry entry for MSIE cookies\n};
        last WIN32_MSIE;
        } # if
      unless (-d $sDir)
        {
        ; _add_error qq{ --- registry entry for MSIE cookies is $sDir but that directory does not exist.\n}
        ; last WIN32_MSIE
        } # unless
      ; my $sFnameCookies = "$sDir\\index.dat"
      ; &_get_cookies($sFnameCookies, 'HTTP::Cookies::Microsoft')
      ; last WIN32_MSIE
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
        _add_error qq{ --- Windows ini file $sFnameWinIni does not exist\n};
        last WIN32_NETSCAPE;
        } # if
      my $oIniWin = new Config::IniFiles(
                                         -file => $sFnameWinIni,
                                        );
      if (! ref($oIniWin))
        {
        _add_error qq{ --- can not parse $sFnameWinIni\n};
        last WIN32_NETSCAPE;
        } # if
      my $sFnameNSIni = $oIniWin->val('Netscape', 'ini');
      if (! -f $sFnameNSIni)
        {
        _add_error qq{ --- Netscape ini file $sFnameNSIni does not exist\n};
        last WIN32_NETSCAPE;
        } # if
      my $oIniNS = Config::IniFiles->new(
                                         -file => $sFnameNSIni,
                                        );
      if (! ref($oIniNS))
        {
        _add_error qq{ --- can not parse $sFnameNSIni\n};
        last WIN32_NETSCAPE;
        } # if
      ; my $sFnameCookies = $oIniNS->val('Cookies', 'Cookie File')
      ; &_get_cookies($sFnameCookies, 'HTTP::Cookies::Netscape')
      ; last WIN32_NETSCAPE;
      } # end of WIN32_NETSCAPE block
    # At this point, $oReal contains Netscape cookies (or undef).
    if (ref($oReal))
      {
      return $oReal if ! wantarray;
      push @aoRet, $oReal;
      } # if found Netscape cookies
    # No more places to look, fall through and return what we've
    # found.
    } # if MSWin32
  elsif (
         ($^O =~ m!solaris!i)
         ||
         ($^O =~ m!linux!i)
        )
    {
    # Unix-like operating systems.
    $oReal = undef;
 UNIX_NETSCAPE4:
      {
      ; my $sFname = catfile(home(), '.netscape', 'cookies')
      ; print STDERR " + try $sFname...\n" if DEBUG_NEW
      ; &_get_cookies($sFname, 'HTTP::Cookies::Netscape')
      ; last UNIX_NETSCAPE4 unless ref($oReal)
      ; push @aoRet, $oReal
      } # end of UNIX_NETSCAPE4 block
    # At this point, $oReal contains Netscape 7 cookies (or undef).
    ; if (ref($oReal))
      {
      ; return $oReal if ! wantarray
      ; push @aoRet, $oReal
      } # if found any cookies
 UNIX_NETSCAPE7:
      {
      ;
      } # end of UNIX_NETSCAPE7 block
    # At this point, $oReal contains Netscape 7 cookies (or undef).
    ; if (ref($oReal))
      {
      ; return $oReal if ! wantarray
      ; push @aoRet, $oReal
      } # if found any cookies
 UNIX_MOZILLA:
    while (1)
      {
      ; eval q{use HTTP::Cookies::Mozilla}
      ; my $sAppregFname = catfile(home(), '.mozilla', 'appreg')
      # ; print STDERR " + try to read appreg ==$sAppregFname==\n"
      ; if (! -f $sAppregFname)
        {
        ; _add_error qq{ --- Mozilla file $sAppregFname does not exist\n};
        ; last UNIX_MOZILLA
        } # if
      ; my $sAppreg
      ; eval { $sAppreg = read_file($sAppregFname, binmode => ':raw') }
      ; $sAppreg ||= '';
      ; my ($sDir) = ($sAppreg =~ m!(.mozilla/.+?\.slt)\b!)
      # ; print STDERR " + found slt ==$sDir==\n"
      ; my $sFname = catfile(home(), $sDir, 'cookies.txt')
      # ; print STDERR " + try to read cookies ==$sFname==\n"
      ; &_get_cookies($sFname, 'HTTP::Cookies::Mozilla')
      ; last UNIX_MOZILLA
      } # end of UNIX_MOZILLA block
    # At this point, $oReal contains Mozilla cookies (or undef).
    # ; print STDERR " +   After mozilla cookie check, oReal is ==$oReal==\n"
    ; if (ref($oReal))
      {
      ; return $oReal if ! wantarray
      # ; print STDERR " +   wantarray, keep looking\n"
      ; push @aoRet, $oReal
      } # if found Mozilla cookies
    } # if solaris
  else
    {
    # Future expansion: implement Netscape / other OS combinations
    }
  return wantarray ? @aoRet : $oReal;
  } # new


sub _get_cookies
  {
  # Required arg1 = cookies filename:
  my $sFnameCookies = shift;
  # Required arg2 = cookies object type:
  my $sClass = shift;
  my $rcCallback = ($sClass =~ m!Microsoft!)
  ? \&_callback_msie
  : ($sClass =~ m!Netscape!)
  ? \&_callback_mozilla
  : ($sClass =~ m!Mozilla!)
  ? \&_callback_mozilla
  : \&_callback_mozilla;
  # Our return value is an object of type HTTP::Cookies.
  print STDERR " + _get_cookies($sFnameCookies,$sClass)\n" if DEBUG_GET;
  if (! -f $sFnameCookies)
    {
    _add_error qq{ --- cookies file $sFnameCookies does not exist\n};
    return undef;
    } # if
  # Because $oReal is a global variable, force creation of a new
  # object into a new variable:
  my $oRealNS = $sClass->new;
  unless (ref $oRealNS)
    {
    _add_error qq{ --- can not create an empty $sClass object.\n};
    return undef;
    } # unless
  print STDERR " +   created oRealNS ==$oRealNS==...\n" if DEBUG_GET;
  $oReal = $oRealNS;
  # This is a dummy object that we use to find the appropriate
  # cookies:
  my $oDummy = $sClass->new(
                            File => $sFnameCookies,
                            'delayload' => 1,
                           );
  unless (ref $oDummy)
    {
    _add_error qq{ --- can not create an empty $sClass object.\n};
    return undef;
    } # unless
  print STDERR " +   created oDummy ==$oDummy==...\n" if DEBUG_GET;
  $oDummy->scan($rcCallback) if ref($oDummy);
  print STDERR " +   return oReal ==$oReal==...\n" if DEBUG_GET;
  return $oReal;
  } # _get_cookies


sub _callback_msie
  {
  my ($version,
      $key, $val,
      $path, $domain, $port, $path_spec,
      $secure, $expires, $discard, $hash) = @_;
  # All we care about at this level is the filename, which is in the
  # $val slot:
  print STDERR " + consider cookie, val==$val==\n" if (DEBUG_NEW);
  return unless ($val =~ m!\@.*$sHostGlobal!i);
  print STDERR " +   matches host ($sHostGlobal)\n" if (1 < DEBUG_NEW);
  return unless ($val =~ m!\\$sUser\@!);
  print STDERR " +   matches user ($sUser)\n" if (1 < DEBUG_NEW);
  # This cookie file matches the user and host.  Add it to the cookies
  # we'll keep:
  $oReal->load_cookie($val);
  } # _callback_msie

sub _callback_mozilla
  {
  # print STDERR " + _callback got a cookie: ", Dumper(\@_);
  # return;
  # my ($version,
  #     $key, $val,
  #     $path, $domain, $port, $path_spec,
  #     $secure, $expires, $discard, $hash) = @_;
  my $sDomain = $_[4];
  print STDERR " +   consider cookie from domain ($sDomain), want host ($sHostGlobal)...\n" if DEBUG_NEW;
  return if (($sHostGlobal ne '') && ($sDomain !~ m!$sHostGlobal!i));
  print STDERR " +     domain ($sDomain) matches host ($sHostGlobal)\n" if DEBUG_NEW;
  $oReal->set_cookie(@_);
  } # _callback_mozilla

=head1 BUGS

Please notify the author if you find any.

=head1 AUTHOR

Martin Thurn E<lt>mthurn@cpan.orgE<gt>

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

HTTP::Cookies, HTTP::Cookies::Microsoft, HTTP::Cookies::Mozilla, HTTP::Cookies::Netscape

=cut

1;

__END__

