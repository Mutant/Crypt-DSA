# $Id: 04-pem.t,v 1.4 2001/04/22 23:58:39 btrott Exp $

use strict;

use Test;
use Crypt::DSA;
use Crypt::DSA::Key;

my $no_pem;
BEGIN {
    eval "use Convert::PEM;";
    $no_pem = $@;
    if ($no_pem) {
        print "1..0 skipping\n";
        exit;
    }

    plan tests => 12;
}


my $keyfile = "./dsa-key.pem";

my $dsa = Crypt::DSA->new;
my $key = $dsa->keygen( Size => 512 );
my $key2;

skip($no_pem, $key->write( Type => 'PEM', Filename => $keyfile));
$key2 = Crypt::DSA::Key->new( Type => 'PEM', Filename => $keyfile );
skip($no_pem, $key->p, $key2->p);
skip($no_pem, $key->q, $key2->q);
skip($no_pem, $key->g, $key2->g);
skip($no_pem, $key->pub_key, $key2->pub_key);
skip($no_pem, $key->priv_key, $key2->priv_key);

skip($no_pem, $key->write( Type => 'PEM', Filename => $keyfile, Password => 'foo'));
$key2 = Crypt::DSA::Key->new( Type => 'PEM', Filename => $keyfile, Password => 'foo' );
skip($no_pem, $key->p, $key2->p);
skip($no_pem, $key->q, $key2->q);
skip($no_pem, $key->g, $key2->g);
skip($no_pem, $key->pub_key, $key2->pub_key);
skip($no_pem, $key->priv_key, $key2->priv_key);

unlink $keyfile;
