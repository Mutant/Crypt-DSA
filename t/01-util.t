# $Id: 01-util.t,v 1.1 2001/04/21 08:40:01 btrott Exp $

use strict;

use Test;
use Math::Pari;
use Crypt::DSA::Util qw( bin2mp bitsize mod_exp mod_inverse );

BEGIN { plan tests => 10 }

my($string, $num, $n);

$string = "abcdefghijklmnopqrstuvwxyz-0123456789";
$num = PARI("48431489725691895261376655659836964813311343892465012587212197286379595482592365885470777");
$n = bin2mp($string);
ok($n, $num);
ok(bitsize($num), 295);
ok(bitsize($n), 295);

$string = "abcd";
$num = 1_633_837_924;
$n = bin2mp($string);
ok($n, $num);
ok(bitsize($num), 31);
ok(bitsize($n), 31);

$string = "";
$num = 0;
$n = bin2mp($string);
ok($n, $num);

my($n1, $n2, $n3, $n4);
($n1, $n2, $n3, $n4) = map PARI($_), ("23098230958", "35", "10980295809854", "5115018827600");
$num = mod_exp($n1, $n2, $n3);
ok($num, $n4);

($n1, $n2, $n3) = map PARI($_), ("34093840983", "23509283509", "7281956166");
$num = mod_inverse($n1, $n2);
ok($num, $n3);
ok(1, ($n1*$num)%$n2);
