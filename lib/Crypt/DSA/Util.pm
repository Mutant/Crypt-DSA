# $Id: Util.pm,v 1.5 2001/03/24 00:18:50 btrott Exp $

package Crypt::DSA::Util;
use strict;

use Math::Pari qw( PARI pari2num floor Mod lift );

use vars qw( @EXPORT_OK @ISA );
use Exporter;
@EXPORT_OK = qw( bitsize bin2mp mod_inverse mod_exp );
@ISA = qw( Exporter );

## Nicked from Crypt::RSA::DataFormat.
## Copyright (c) 2001, Vipul Ved Prakash.
sub bitsize {
    return pari2num(floor(Math::Pari::log($_[0])/Math::Pari::log(2)) + 1);
}

sub bin2mp {
    my $s = shift;
    my $p = PARI(0);
    for my $b (split //, $s) {
        $p = $p * 256 + ord $b;
    }
    $p;
}

sub mod_exp {
    my($a, $exp, $n) = @_;
    my $m = Mod($a, $n);
    lift($m ** $exp);
}

sub mod_inverse {
    my($a, $n) = @_;
    my $m = Mod(1, $n);
    lift($m / $a);
}

1;
__END__

=head1 NAME

Crypt::DSA::Util - DSA Utility functions

=head1 SYNOPSIS

    use Crypt::DSA::Util qw( func1 func2 ... );

=head1 DESCRIPTION

I<Crypt::DSA::Util> contains a set of exportable utility functions
used through the I<Crypt::DSA> set of libraries.

=head2 bitsize($n)

Returns the number of bits in the I<Math::Pari> integer object
I<$n>.

=head2 bin2mp($string)

Given a string I<$string> of any length, treats the string as a
base-256 representation of an integer, and returns that integer,
a I<Math::Pari> object.

=head2 mod_exp($a, $exp, $n)

Computes $a ^ $exp mod $n and returns the value. The calculations
are done using I<Math::Pari>, and the return value is a I<Math::Pari>
object.

=head2 mod_inverse($a, $n)

Computes the multiplicative inverse of $a mod $n and returns the
value. The calculations are done using I<Math::Pari>, and the
return value is a I<Math::Pari> object.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::DSA manpage for author, copyright,
and license information.

=cut
