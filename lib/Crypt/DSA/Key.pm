# $Id: Key.pm,v 1.2 2001/03/23 23:21:06 btrott Exp $

package Crypt::DSA::Key;
use strict;

sub new {
    my $class = shift;
    bless { @_ }, $class;
}

BEGIN {
    no strict 'refs';
    for my $meth (qw( p q g pub_key priv_key r kinv )) {
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

Crypt::DSA::Key - DSA key

=head1 SYNOPSIS

    use Crypt::DSA::Key;
    my $key = Crypt::DSA::Key->new;

    $key->p($p);

=head1 DESCRIPTION

I<Crypt::DSA::Key> contains a DSA key, both the public and
private portions.

Any of the key attributes can be accessed through combination
get/set methods. The key attributes are: I<p>, I<q>, I<g>,
I<priv_key>, and I<pub_key>. For example:

    $key->p($p);
    my $p2 = $key->p;

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::DSA manpage for author, copyright,
and license information.

=cut
