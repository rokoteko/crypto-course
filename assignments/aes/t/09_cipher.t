#!/usr/bin/env perl

use strict;
use warnings;

use lib '../lib';
use Test::More tests => 1;
use Test::Deep;

use AES;

my $c = AES->new();

my @key = (
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
);

my $in = [
    [0x32, 0x88, 0x31, 0xe0],
    [0x43, 0x5a, 0x31, 0x37],
    [0xf6, 0x30, 0x98, 0x07],
    [0xa8, 0x8d, 0xa2, 0x34],
];

my $out_ok = [
    [0x39, 0x02, 0xdc, 0x19],
    [0x25, 0xdc, 0x11, 0x6a],
    [0x84, 0x09, 0x85, 0x0b],
    [0x1d, 0xfb, 0x97, 0x32],
];

my @W = $c->key_expansion(@key);

my $out = $c->cipher($in, @W);

cmp_deeply(
    $out,
    $out_ok,
    "cipher output correct",
);

