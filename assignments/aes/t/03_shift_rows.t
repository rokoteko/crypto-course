#!/usr/bin/env perl

use strict;
use warnings;

use lib '../lib';
use Test::More tests => 1;
use Test::Deep;

use AES;

my $c = AES->new();

my $in  = [
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
];

my $out = [
    [1, 2, 3, 4],
    [2, 3, 4, 1],
    [3, 4, 1, 2],
    [4, 1, 2, 3],
];

my $res = $c->shift_rows($in);

cmp_deeply(
    $res,
    $out,
    "rotated array correctly",
);

