#line 1 "C:/DOCUMENTS/MARTIN/Modules/HTTP-Cookies-Find/inc/Module/Install.pm - c:/perl/site/lib/Module/Install.pm"
package Module::Install;
use 5.004;

$VERSION = '0.44';

die << "." unless $INC{join('/', inc => split(/::/, __PACKAGE__)).'.pm'};
Please invoke ${\__PACKAGE__} with:

    use inc::${\__PACKAGE__};

not:

    use ${\__PACKAGE__};

.

use strict 'vars';
use Cwd qw(cwd abs_path);
use FindBin;
use File::Find ();
use File::Path ();

@inc::Module::Install::ISA = 'Module::Install';
*inc::Module::Install::VERSION = *VERSION;

sub autoload {
    my $self   = shift;
    my $caller = $self->_caller;

    my $cwd = cwd();
    my $sym = "$caller\::AUTOLOAD";

    $sym->{$cwd} = sub {
        my $pwd = cwd();
        if (my $code = $sym->{$pwd}) {
            goto &$code unless $cwd eq $pwd; # delegate back to parent dirs
        }
        $$sym =~ /([^:]+)$/ or die "Cannot autoload $caller - $sym";
        unshift @_, ($self, $1);
        goto &{$self->can('call')} unless uc($1) eq $1;
    };
}

sub import {
    my $class = shift;
    my $self = $class->new(@_);

    if (not -f $self->{file}) {
        require "$self->{path}/$self->{dispatch}.pm";
        File::Path::mkpath("$self->{prefix}/$self->{author}");
        $self->{admin} = 
          "$self->{name}::$self->{dispatch}"->new(_top => $self);
        $self->{admin}->init;
        @_ = ($class, _self => $self);
        goto &{"$self->{name}::import"};
    }

    *{$self->_caller . "::AUTOLOAD"} = $self->autoload;
    $self->preload;

    # Unregister loader and worker packages so subdirs can use them again
    delete $INC{"$self->{file}"};
    delete $INC{"$self->{path}.pm"};
}

sub preload {
    my ($self) = @_;

    $self->load_extensions(
        "$self->{prefix}/$self->{path}", $self
    ) unless $self->{extensions};

    my @exts = @{$self->{extensions}};

    unless (@exts) {
        my $admin = $self->{admin};
        @exts = $admin->load_all_extensions;
    }

    my %seen_method;
    foreach my $obj (@exts) {
        while (my ($method, $glob) = each %{ref($obj) . '::'}) {
            next unless defined *{$glob}{CODE};
            next if $method =~ /^_/;
            next if $method eq uc($method);
            $seen_method{$method}++;
        }
    }

    my $caller = $self->_caller;
    foreach my $name (sort keys %seen_method) {
        *{"${caller}::$name"} = sub {
            ${"${caller}::AUTOLOAD"} = "${caller}::$name";
            goto &{"${caller}::AUTOLOAD"};
        };
    }
}

sub new {
    my ($class, %args) = @_;

    # ignore the prefix on extension modules built from top level.
    my $base_path = abs_path($FindBin::Bin);
    delete $args{prefix} unless abs_path(cwd()) eq $base_path;

    return $args{_self} if $args{_self};

    $args{dispatch} ||= 'Admin';
    $args{prefix}   ||= 'inc';
    $args{author}   ||= '.author';
    $args{bundle}   ||= 'inc/BUNDLES';
    $args{base}     ||= $base_path;

    $class =~ s/^\Q$args{prefix}\E:://;
    $args{name}     ||= $class;
    $args{version}  ||= $class->VERSION;

    unless ($args{path}) {
        $args{path}  = $args{name};
        $args{path}  =~ s!::!/!g;
    }
    $args{file}     ||= "$args{base}/$args{prefix}/$args{path}.pm";

    bless(\%args, $class);
}

sub call {
    my $self   = shift;
    my $method = shift;
    my $obj    = $self->load($method) or return;

    unshift @_, $obj;
    goto &{$obj->can($method)};
}

sub load {
    my ($self, $method) = @_;

    $self->load_extensions(
        "$self->{prefix}/$self->{path}", $self
    ) unless $self->{extensions};

    foreach my $obj (@{$self->{extensions}}) {
        return $obj if $obj->can($method);
    }

    my $admin = $self->{admin} or die << "END";
The '$method' method does not exist in the '$self->{prefix}' path!
Please remove the '$self->{prefix}' directory and run $0 again to load it.
END

    my $obj = $admin->load($method, 1);
    push @{$self->{extensions}}, $obj;

    $obj;
}

sub load_extensions {
    my ($self, $path, $top_obj) = @_;

    unshift @INC, $self->{prefix}
        unless grep { $_ eq $self->{prefix} } @INC;

    local @INC = ($path, @INC);
    foreach my $rv ($self->find_extensions($path)) {
        my ($file, $pkg) = @{$rv};
        next if $self->{pathnames}{$pkg};

        local $@;
        my $new = eval { require $file; $pkg->can('new') };
        if (!$new) { warn $@ if $@; next; }
        $self->{pathnames}{$pkg} = delete $INC{$file};
        push @{$self->{extensions}}, &{$new}($pkg, _top => $top_obj );
    }

    $self->{extensions} ||= [];
}

sub find_extensions {
    my ($self, $path) = @_;
    my @found;

    File::Find::find(sub {
        my $file = $File::Find::name;
        return unless $file =~ m!^\Q$path\E/(.+)\.pm\Z!is;
        return if $1 eq $self->{dispatch};

        $file = "$self->{path}/$1.pm";
        my $pkg = "$self->{name}::$1"; $pkg =~ s!/!::!g;
        push @found, [$file, $pkg];
    }, $path) if -d $path;

    @found;
}

sub _caller {
    my $depth = 0;
    my $caller = caller($depth);

    while ($caller eq __PACKAGE__) {
        $depth++;
        $caller = caller($depth);
    }

    $caller;
}

1;
