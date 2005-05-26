# $Id: Makefile.PL 1830 2005-05-25 21:58:57Z btrott $

use inc::Module::Install;

name('Crypt-DSA');
abstract('DSA signatures and key generation');
author('Benjamin Trott <cpan@stupidfool.org>');
version_from('lib/Crypt/DSA.pm');
license('perl');
no_index(directory => 't');
sign(1);

include('ExtUtils::AutoInstall');

requires('Math::BigInt' => '1.60');
requires('Digest::SHA1');

features(
    'Read/write PEM-encoded files' => [
        -default => 0,
        recommends('Convert::PEM' => '0.07'),
    ],

    'Read/write SSH2 keyfiles' => [
        -default => 0,
        recommends('Data::Buffer' => '0.01'),
    ],
);

auto_include();
auto_install();

&WriteAll;
