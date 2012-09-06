package AES;

use strict;
use warnings;

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

    $m->setval(0, 0, [0x02, 0x03, 0x01, 0x01]);
    $m->setval(1, 0, [0x01, 0x02, 0x03, 0x01]);
    $m->setval(2, 0, [0x01, 0x01, 0x02, 0x03]);
    $m->setval(3, 0, [0x03, 0x01, 0x01, 0x02]);

    $self->{mix_column_mul_mat} = $m;

}

sub mix_columns {
    my ($self, $in) = @_;

    # NOT WORKING!!
    #
warn "IN: " . Data::Dumper::Dumper( $in );
    my $col = Math::FastGF2::Matrix->new(
        rows    => 1,
        cols    => 4,
        width   => 1,
    );

    for my $i (0..3) {
        my $val = $in->[$i][0];
warn "ROW [$i], COL [0], VAL [$val]";
        $col->setval($i, 0, $in->[$i][0]);
    }
warn "COL: " . Data::Dumper::Dumper( $col );
}


sub mix_column {
    my ($self, $col, $in) = @_;
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


