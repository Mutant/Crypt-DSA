# $Id: Makefile.PL,v 1.3 2001/03/23 22:27:25 btrott Exp $

use ExtUtils::MakeMaker;

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
