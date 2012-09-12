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

my $state = [
    [0x2b, 0x28, 0xab, 0x09],
    [0x7e, 0xae, 0xf7, 0xcf],
    [0x15, 0xd2, 0x15, 0x4f],
    [0x16, 0xa6, 0x88, 0x3c],
];

my $out = [
    [0x19, 0xa0, 0x9a, 0xe9],
    [0x3d, 0xf4, 0xc6, 0xf8],
    [0xe3, 0xe2, 0x8d, 0x48],
    [0xbe, 0x2b, 0x2a, 0x08],
];

my @W = $c->key_expansion(@key);

warn "STATE BEFORE: " . Data::Dumper::Dumper( $state );

$c->add_round_key($state, 1, @W);

warn "STATE AFTER: " . Data::Dumper::Dumper( $state );

warn "EXPECTING OUT: " . Data::Dumper::Dumper( $out );


#for my $i (0..$#res) {
#    warn "RES[$i]: " . unpack "H*", $res[$i];
#}

#is( scalar @res, 44, 'maybe expanded key correctly' );

cmp_deeply(
    $state,
    $out,
    "added round key correctly",
);

