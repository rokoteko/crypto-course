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

my @res = $c->key_expansion(@key);
#for my $i (0..$#res) {
#    warn "RES[$i]: " . unpack "H*", $res[$i];
#}

is( scalar @res, 44, 'maybe expanded key correctly' );

#cmp_deeply(
#    $res,
#    $out,
#    "subtitute bytes correctly",
#);

