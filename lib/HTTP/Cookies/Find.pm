
# $rcs = ' $Id: Find.pm,v 1.2 2003-12-01 23:54:19-05 kingpin Exp kingpin $ ' ;

package HTTP::Cookies::Find;
use strict;

use Carp;
use Exporter ();
use vars qw( @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS );
@ISA         = qw( Exporter HTTP::Cookies );
# Give a hoot don't pollute, do not export more than needed by default
@EXPORT      = qw( );
@EXPORT_OK   = qw( );
%EXPORT_TAGS = ();

my
$VERSION = sprintf("%d.%02d", q$Revision: 1.2 $ =~ /(\d+)\.(\d+)/o);

use User;

=head1 NAME

HTTP::Cookies::Find - Locate cookies for the current user on the local machine.

=head1 SYNOPSIS

  use HTTP::Cookies::Find;
  my $oCookies = HTTP::Cookies::Find->new('domain.com');
  # $oCookies is a subclass of HTTP::Cookies

=head1 DESCRIPTION



=head1 USAGE



=cut

############################################# main pod documentation end ##

use constant DEBUG_NEW => 0;

# We use global variables so that the callback function can see them:
use vars qw( $sUser $sHost $oReal );

sub new
  {
  my $class = shift;
  $sHost = lc shift || '';
  # Massage the hostname in an attempt to make it match MS' highlevel
  # naming scheme:
  $sHost =~ s!\.(com|edu|gov|net|org)\Z!!;  # delete USA domain
  $sHost =~ s!\.[a-z][a-z]\.[a-z][a-z]\Z!!;  # delete intl domain
  # We only look at cookies for the logged-in user:
  $sUser = lc User->Login;
  print STDERR " + Finding cookies for user $sUser...\n" if DEBUG_NEW;
  if ($^O =~ m!win32!i)
    {
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
      return undef;
      } # if
    if ($sDir eq '')
      {
      carp qq{ --- can not find registry entry for MSIE cookies\n};
      return undef;
      } # if
    unless (-d $sDir)
      {
      carp qq{ --- registry entry for MSIE cookies is $sDir but that directory does not exist.\n};
      return undef;
      } # unless
    # This will be the object we return:
    $oReal = HTTP::Cookies::Microsoft->new;
    unless (ref $oReal)
      {
      carp qq{ --- can not create an HTTP::Cookies::Microsoft object.\n};
      return undef;
      } # unless
    # This is a dummy object that we use to find the appropriate
    # cookies:
    my $oDummy = HTTP::Cookies::Microsoft->new(
                                               File => "$sDir\\index.dat",
                                               'delayload' => 1,
                                              );
    $oDummy->scan(\&callback);
    } # if MSWin32
  else
    {
    # Future expansion: implement Netscape / other OS conbinations
    }
  return ($oReal);
  } # new


sub callback
  {
  my ($version,
      $key, $val,
      $path, $domain, $port, $path_spec,
      $secure, $expires, $discard, $hash) = @_;
  # All we care about at this level is the filename, which is in the
  # $val slot:
  print STDERR " + consider cookie, val==$val==\n" if (1 < DEBUG_NEW);
  return unless ($val =~ m!\@.*$sHost!);
  print STDERR " +   matches host ($sHost)\n" if DEBUG_NEW;
  return unless ($val =~ m!$sUser\@!);
  print STDERR " +   matches user ($sUser)\n" if DEBUG_NEW;
  # This cookie file matches the user and host.  Add it to the cookies
  # we'll keep:
  $oReal->load_cookie($val);
  } # callback

=head1 BUGS


=head1 SUPPORT


=head1 AUTHOR

Martin Thurn E<lt>mthurn@cpan.orgE<gt>

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

perl(1).

=cut

1;

__END__

