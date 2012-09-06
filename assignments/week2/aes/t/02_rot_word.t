#!/usr/bin/env perl

use strict;
use warnings;

use lib '../lib';
use Test::More tests => 1;
use Test::Deep;

use AES;

my $c = AES->new();

my @in  = (0, 1, 2, 3);
my @out = (1, 2, 3, 0);

my @res = $c->rot_word(@in);

cmp_deeply(
    \@res,
    \@out,
    "rotated array correctly",
);

