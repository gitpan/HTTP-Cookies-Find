use ExtUtils::testlib;
# use LWP::Debug qw( + );  # So we can see more error messages, if any
use Test::More no_plan;

BEGIN { use_ok('Data::Dumper') };
BEGIN { use_ok('HTTP::Cookies::Find') };

use vars qw( $iCount );
use warnings;

SKIP:
  {
  skip 'This is not Solaris', 8 if ($^O !~ m!solaris!i);

  my $o = new HTTP::Cookies::Find(q{there better not be any host in the world that matches this});
  ok(ref $o, 'new');
  is(ref($o), 'HTTP::Cookies::Netscape');
  $iCount = 0;
  $o->scan(\&cb_count);
  is($iCount, 0);

  $o = new HTTP::Cookies::Find();
  ok(ref($o));
  is(ref($o), 'HTTP::Cookies::Netscape');
  $iCount = 0;
  $o->scan(\&cb_count);
  cmp_ok(0, '<', $iCount);
  diag(sprintf(q{You have a total of %d cookies in Netscape}, $iCount));

  my $sHost = 'netscape';
  $o = new HTTP::Cookies::Find($sHost);
  ok(ref $o);
  is(ref($o), 'HTTP::Cookies::Netscape');
  $iCount = 0;
  $o->scan(\&cb_count);
  diag(sprintf(qq{Found %d cookies that match host $sHost}, $iCount));

  if (0)
    {
    diag(q{Here is a list of all the cookies:});
    $o->scan(\&cb_dump);
    } # if
  } # end of SKIP block

sub cb_count
  {
  $iCount++;
  } # cb_count

sub cb_dump
  {
  my ($version,
      $key, $val,
      $path, $domain, $port, $path_spec,
      $secure, $expires, $discard, $hash) = @_;
  # port is usually undef:
  $port ||= '';
  print STDERR " + cookie is as follows:\n";
  print STDERR " +   key==$key==\n";
  print STDERR " +   val==$val==\n";
  print STDERR " +   path==$path==\n";
  print STDERR " +   domain==$domain==\n";
  print STDERR " +   port==$port==\n";
  print STDERR " +   path_spec==$path_spec==\n";
  print STDERR " +   secure==$secure==\n";
  print STDERR " +   expires==$expires==\n";
  print STDERR " +   discard==$discard==\n";
  print STDERR " +   hash==", Dumper($hash);
  } # cb_dump

1;

__END__