#!/usr/bin/env perl

use strict;
use warnings;

use lib '../lib';
use Test::More tests => 1;
use Test::Deep;

use AES;

my $c = AES->new();

my $in  = [
    [0x19, 0xa0, 0x9a, 0xe9],
    [0x3d, 0xf4, 0xc6, 0xf8],
    [0xe3, 0xe2, 0x8d, 0x48],
    [0xbe, 0x2b, 0x2a, 0x08],
];

my $out = [
    [0xd4, 0xe0, 0xb8, 0x1e],
    [0x27, 0xbf, 0xb4, 0x41],
    [0x11, 0x98, 0x5d, 0x52],
    [0xae, 0xf1, 0xe5, 0x30],
];

my $res = $c->sub_bytes($in);

cmp_deeply(
    $res,
    $out,
    "subtitute bytes correctly",
);
