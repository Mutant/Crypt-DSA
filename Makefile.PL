# $Id: Makefile.PL,v 1.5 2001/05/02 07:23:18 btrott Exp $

use ExtUtils::MakeMaker;

my $missing = 0;
print "\nChecking for optional modules\n\n";

unless (check_module('Convert::PEM', 0.04, \$missing)) {
    print<<MSG, "\n";
Convert::PEM (version 0.04 or greater) is required if you want
to read/write PEM-encoded files.
MSG
}
print "\n";

unless (check_module('Data::Buffer', 0.01, \$missing)) {
    print<<MSG, "\n";
Data::Buffer (version 0.01 or greater) if required if you want
to read/write SSH2 keyfiles.
MSG
}
print "\n";

if ($missing) {
    print <<MSG, "\n";
*****************************************************************
You are missing some modules that may be needed for some of the
features in Crypt::DSA to work correctly. If you need these
features, please download any required modules from the CPAN.
*****************************************************************
MSG
}

WriteMakefile(
    NAME => 'Crypt::DSA',
    DISTNAME => 'Crypt-DSA',
    VERSION_FROM => 'lib/Crypt/DSA.pm',
    AUTHOR => 'Benjamin Trott <ben@rhumba.pair.com>',
    ABSTRACT => 'DSA signatures and key generation',
    PREREQ_PM => {
        'Math::Pari' => '2.001804',
        'Digest::SHA1' => 0,
        'Crypt::Random' => '0.33',
    },
);

sub check_module {
    my($name, $ver, $missing) = @_;
    print substr("$name ............................", 0, 30);
    my $ok = have_mod($name, $ver);
    $$missing++ unless $ok;
    print $ok ? "ok\n" : "** FAILED **\n";
    $ok;
}

sub have_mod {
    my($name, $ver) = @_;
    eval("use $name" . ($ver ? " $ver;" : ";"));
    !$@;
}
