# $Id: 03-keygen.t,v 1.2 2001/04/21 08:44:21 btrott Exp $

use strict;

use Test;
use Crypt::DSA;
use Crypt::DSA::Util qw( mod_exp );
use Math::Pari;

BEGIN { plan tests => 15 }

my $dsa = Crypt::DSA->new;

my $two = PARI(2);
for my $bits (qw( 512 768 1024 )) {
    my $key = $dsa->keygen( Size => $bits );
    ok($key);
    ok(($key->p < ($two ** $bits)) && ($key->p > ($two ** ($bits-1))));
    ok(($key->q < ($two ** 160)) && ($key->q > ($two ** 159)));
    ok(0, ($key->p - 1) % $key->q);
    ok($key->pub_key, mod_exp($key->g, $key->priv_key, $key->p));
}
