use ExtUtils::testlib;
use Test::More no_plan;

BEGIN { use_ok('Data::Dumper') };
BEGIN { use_ok('HTTP::Cookies::Find') };

use vars qw( $iCount );

SKIP:
  {
  skip 'This is not Windows', 2 if ($^O !~ m!win32!i);

  my $sHost = 'zap2it';
  diag(qq{Looking for cookies that match host=$sHost...});
  my $o = new HTTP::Cookies::Find($sHost);
  ok(ref $o, 'new');
  is(ref($o), 'HTTP::Cookies::Microsoft');
  # diag(q{The object created is of type }. ref $o);

  $iCount = 0;
  $o->scan(\&cb_count);
  diag(sprintf(q{Found %d cookies}, $iCount));
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
