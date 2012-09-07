package AES;

use strict;
use warnings;
no warnings 'redefine';

use Moo;
use Math::FastGF2::Matrix; 

use Data::Dumper;

our $MIX_COLUMNS_MUL;


sub init {
    my $self = shift;

    my $m = Math::FastGF2::Matrix->new(
        rows    => 4,
        cols    => 4,
        width   => 1,
    );

    $m->setvals(0, 0, [0x02, 0x03, 0x01, 0x01]);
    $m->setvals(1, 0, [0x01, 0x02, 0x03, 0x01]);
    $m->setvals(2, 0, [0x01, 0x01, 0x02, 0x03]);
    $m->setvals(3, 0, [0x03, 0x01, 0x01, 0x02]);

    $self->{mix_columns_mul_mat} = $m;

    return;
}

sub mix_columns {
    my ($self, $in) = @_;

    $self->init() unless $self->{mix_columns_mul_mat};

    my $out = [];

    for my $i (0..3) {
        my $col = $self->mix_column($i, $in);
        $out->[0][$i] = $col->[0];
        $out->[1][$i] = $col->[1];
        $out->[2][$i] = $col->[2];
        $out->[3][$i] = $col->[3];
    }

    return $out;

}

sub mix_column {
    my ($self, $colnum, $in) = @_;

    my $col = Math::FastGF2::Matrix->new(
        rows    => 4,
        cols    => 1,
        width   => 1,
    );

    for my $i (0..3) {
        my $val = $in->[$i][$colnum];
        $col->setval($i, 0, $in->[$i][$colnum]);
    }

    my $res = $self->{mix_columns_mul_mat}->multiply($col);

    my $out = [
        $res->getval(0, 0),
        $res->getval(1, 0),
        $res->getval(2, 0),
        $res->getval(3, 0),
    ];

    return $out;
}

sub shift_rows {
    my ($self, $in) = @_;

    my $res = [];
    $res->[0] = $in->[0];
    $res->[1] = [ $self->rot_array(3, @{ $in->[1] }) ];
    $res->[2] = [ $self->rot_array(2, @{ $in->[2] }) ];
    $res->[3] = [ $self->rot_array(1, @{ $in->[3] }) ];

    return $res;
}

sub rot_word {
    my ($self, @in) = @_;
    return $self->rot_array(3, @in);
}

sub rot_array {
    my ($self, $rot, @in) = @_;
    my @ret;

    for my $i (0..$#in) {
#                    p[ (i-u)     % len(p) ]
        push @ret, $in[ ($i-$rot) % @in ];
    }

    return @ret;
}

1;


