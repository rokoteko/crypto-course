#!/usr/bin/env perl

use strict;
use warnings;

use lib '../lib';
use Test::More tests => 1;
use Test::Deep;

use AES;

my $c = AES->new();

my $in  = pack "C4", 0xcf, 0x4f, 0x3c, 0x09;
my $out = pack "C4", 0x8a, 0x84, 0xeb, 0x01;

my $res = $c->sub_word($in);

ok( $res eq $out, "sub_word substitution correct");

