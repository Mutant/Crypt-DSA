# $Id: Signature.pm,v 1.1 2001/03/31 08:44:51 btrott Exp $

package Crypt::DSA::Signature;
use strict;

sub new {
    my $class = shift;
    bless { @_ }, $class;
}

BEGIN {
    no strict 'refs';
    for my $meth (qw( s r )) {
        *$meth = sub {
            my $key = shift;
            $key->{$meth} = shift if @_;
            $key->{$meth}
        };
    }
}

1;
__END__

=head1 NAME

Crypt::DSA::Signature - DSA signature object

=head1 SYNOPSIS

    use Crypt::DSA::Signature;
    my $sig = Crypt::DSA::Signature->new;

    $sig->r($r);
    $sig->s($s);

=head1 DESCRIPTION

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::DSA manpage for author, copyright,
and license information.

=cut
