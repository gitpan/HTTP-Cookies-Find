use ExtUtils::testlib;
use Test::More no_plan;

BEGIN { use_ok('Data::Dumper') };
BEGIN { use_ok('HTTP::Cookies::Find') };

use vars qw( $iCount );

SKIP:
  {
  skip 'This is not Windows', 8 if ($^O !~ m!win32!i);

  diag(q{Using real MSIE info from your system});
  # goto DEBUG_NOW;
  my $o = new HTTP::Cookies::Find(q{no host in the world matches this});
  &dump_errors;
  isa_ok($o, 'HTTP::Cookies::Microsoft');
  $iCount = 0;
  $o->scan(\&cb_count);
  is($iCount, 0);

  $o = new HTTP::Cookies::Find();
  &dump_errors;
  isa_ok($o, 'HTTP::Cookies::Microsoft');
  # diag(q{The object created is of type }. ref $o);
  $iCount = 0;
  $o->scan(\&cb_count);
  cmp_ok(0, '<', $iCount);
  diag(sprintf(q{You have a total of %d cookies in MSIE}, $iCount));

  my $sHost = 'soft';
  $o = new HTTP::Cookies::Find($sHost);
  &dump_errors;
  isa_ok($o, 'HTTP::Cookies::Microsoft');
  $iCount = 0;
  $o->scan(\&cb_count);
  diag(sprintf(qq{Found %d MSIE cookies that match host $sHost}, $iCount));

  $sHost = qr'go+gle';
  $o = new HTTP::Cookies::Find($sHost);
  &dump_errors;
  isa_ok($o, 'HTTP::Cookies::Microsoft');
  $iCount = 0;
  $o->scan(\&cb_count);
  cmp_ok(0, '<', $iCount);
  diag(sprintf(qq{Found %d MSIE cookies that match host $sHost}, $iCount));

  if (0)
    {
    diag(q{Here is a list of all the cookies:});
    $o->scan(\&cb_dump);
    } # if

 DEBUG_NOW:
  # Now call array context.
  $sHost = 'ebay';
  # Trick it into finding our test files:
  $ENV{WINDIR} = './t';
  diag(qq{Using fake Netscape info from directory $ENV{WINDIR}});
  my @ao1 = HTTP::Cookies::Find->new($sHost);
  &dump_errors;
  foreach my $o1 (@ao1)
    {
    ok(ref($o1));
    my $sBrowser = ref($o1);
    $sBrowser =~ s!.*::!!;
    $iCount = 0;
    $o1->scan(\&cb_count);
    diag(sprintf(qq{Found %d cookies for $sBrowser\'s browser that match host $sHost}, $iCount));
    } # foreach

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

sub dump_errors
  {
  foreach my $sError (HTTP::Cookies::Find::errors)
    {
    diag($sError);
    } # foreach
  } # dump_errors

1;

__END__
