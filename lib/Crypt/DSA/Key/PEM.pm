# $Id: PEM.pm,v 1.6 2001/04/22 08:03:04 btrott Exp $

package Crypt::DSA::Key::PEM;
use strict;

use Convert::PEM;

use Crypt::DSA::Key;
use base qw( Crypt::DSA::Key );

sub deserialize {
    my $key = shift;
    my %param = @_;

    my $pem = $key->_pem;
    my $pkey = $pem->decode( Content  => $param{Content},
                             Password => $param{Password} );
    return unless $pkey;

    for my $m (qw( p q g pub_key priv_key )) {
        $key->$m( $pkey->{DSAPrivateKey}{$m} );
    }
    $key;
}

sub serialize {
    my $key = shift;
    my %param = @_;

    my $pkey = { DSAPrivateKey => { version => 0 } };
    for my $m (qw( p q g pub_key priv_key )) {
        $pkey->{DSAPrivateKey}{$m} = $key->$m();
    }

    my $pem = $key->_pem;
    my $buf = $pem->encode(
            Content  => $pkey,
            Password => $param{Password}
        ) or croak $pem->errstr;
    $buf;
}

sub _pem {
    my $key = shift;
    unless (defined $key->{__pem}) {
        my $pem = Convert::PEM->new(
             Name => "DSA PRIVATE KEY",
             ASN  => qq(
                 DSAPrivateKey SEQUENCE {
                     version INTEGER,
                     p INTEGER,
                     q INTEGER,
                     g INTEGER,
                     pub_key INTEGER,
                     priv_key INTEGER
                 }
           ));
        $pem->asn->configure( decode => { bigint => 'Math::Pari' },
                              encode => { bigint => 'Math::Pari' } );
        $key->{__pem} = $pem;
    }
    $key->{__pem};
}

1;
__END__

=head1 NAME

Crypt::DSA::Key::PEM - Read/write DSA PEM files

=head1 SYNOPSIS

    use Crypt::DSA::Key;
    my $key = Crypt::DSA::Key->new( Type => 'PEM', ...);
    $key->write( Type => 'PEM', ...);

=head1 DESCRIPTION

I<Crypt::DSA::Key::PEM> provides an interface to reading and
writing DSA PEM files, using I<Convert::PEM>. The files are
ASN.1-encoded and optionally encrypted.

You shouldn't use this module directly. As the SYNOPSIS above
suggests, this module should be considered a plugin for
I<Crypt::DSA::Key>, and all access to PEM files (reading DSA
keys from disk, etc.) should be done through that module.

Read the I<Crypt::DSA::Key> documentation for more details.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::DSA manpage for author, copyright,
and license information.

=cut
