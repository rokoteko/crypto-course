package AES;

use strict;
use warnings;
no warnings 'redefine';

use Moo;
use Math::FastGF2 'gf2_inv';
use Math::FastGF2::Matrix; 

use Data::Dumper;

our @SBOX = (
     99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118,
    202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
    183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21,
      4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117,
      9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
     83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207,
    208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,
     81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210,
    205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115,
     96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
    224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121,
    231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8,
    186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138,
    112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158,
    225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
    140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22,
);

our @Rcon = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
    0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
);


our $Nb = 4;  # Number of columns (32-bit words) comprising the State
our $Nk = 4;  # Number of 32-bit words comprising the Cipher Key
our $Nr = 10; # Number of rounds

sub init {
    my $self = shift;

    # multiplication matrix for mix_columns
    my $m1 = Math::FastGF2::Matrix->new(
        rows    => 4,
        cols    => 4,
        width   => 1,
    );

    $m1->setvals(0, 0, [0x02, 0x03, 0x01, 0x01]);
    $m1->setvals(1, 0, [0x01, 0x02, 0x03, 0x01]);
    $m1->setvals(2, 0, [0x01, 0x01, 0x02, 0x03]);
    $m1->setvals(3, 0, [0x03, 0x01, 0x01, 0x02]);

    $self->{mix_columns_mul_mat} = $m1;

    # multiplication matrix for sub_bytes
    my $m2 = Math::FastGF2::Matrix->new(
        rows    => 8,
        cols    => 8,
        width   => 1,
    );

    $m2->setvals(0, 0, [1, 0, 0, 0, 1, 1, 1, 1]);
    $m2->setvals(1, 0, [1, 1, 0, 0, 0, 1, 1, 1]);
    $m2->setvals(2, 0, [1, 1, 1, 0, 0, 0, 1, 1]);
    $m2->setvals(3, 0, [1, 1, 1, 1, 0, 0, 0, 1]);
    $m2->setvals(4, 0, [1, 1, 1, 1, 1, 0, 0, 0]);
    $m2->setvals(5, 0, [0, 1, 1, 1, 1, 1, 0, 0]);
    $m2->setvals(6, 0, [0, 0, 1, 1, 1, 1, 1, 0]);
    $m2->setvals(7, 0, [0, 0, 0, 1, 1, 1, 1, 1]);

    $self->{sub_bytes_mul_mat} = $m2;

    return;
}

sub key_expansion {
    my ($self, @key) = @_;

#our $Nb = 4;  # Number of columns (32-bit words) comprising the State
#our $Nk = 4;  # Number of 32-bit words comprising the Cipher Key
#our $Nr = 10; # Number of rounds

#KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
#begin
#    word temp
#
#    i = 0
#    while (i < Nk)
#        w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
#        i = i+1
#    end while
#
#    i = Nk
#
#    while (i < Nb * (Nr+1)]
#        temp = w[i-1]
#        if (i mod Nk = 0)
#            temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
#        else if (Nk > 6 and i mod Nk = 4)
#            temp = SubWord(temp)
#        end if
#        w[i] = w[i-Nk] xor temp
#        i = i + 1
#    end while
#end

    my @W;
    $W[0] = pack "C4", @key[0..3];
    $W[1] = pack "C4", @key[4..7];
    $W[2] = pack "C4", @key[8..11];
    $W[3] = pack "C4", @key[12..15];

    my $i = $Nk;
    while ($i < $Nb * ($Nr+1)) {
        my $temp = $W[$i-1];

        my $byte1 = $Rcon[($i/$Nk) - 1];
        my $rcon  = pack "C4", $byte1, 0x00, 0x00, 0x00;
        if ($i % $Nk == 0) {
            $temp = $self->sub_word($self->rot_word($temp)) ^ $rcon;
        } elsif ($Nk > 6 and $i % $Nk == 4) {
            $temp = $self->sub_word($temp);
        }
        $W[$i] = $W[$i-$Nk] ^ $temp;
        $i++;
    }

    return @W;
}

sub sub_word {
    my ($self, $word) = @_;
    my @bytes = unpack "C4", $word;

    my @subs;
    for my $byte (@bytes) {
            push @subs, $SBOX[$byte];
    }

    return pack "C4", @subs;
}

sub sub_bytes {
    my ($self, $state) = @_;

    my $out = [];

    for my $row_num (0..$#$state) {
        warn "LOOPING ROW [$row_num] IN STATE.";

        for my $col_num (0..$#{ $state->[$row_num] }) {

            my $b = $state->[$row_num][$col_num];
            warn "GOT BYTE [" . sprintf("0x%x", $b) . "]";

            push @{ $out->[$row_num] }, $SBOX[$b];
        }
    }

    return $out;
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
    my ($self, $in) = @_;

    my @bytes = unpack "C4", $in;
    my @rotated = $self->rot_array(3, @bytes);
    return pack "C4", @rotated;
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


#sub sub_bytes_no_lookup {
#    my ($self, $state) = @_;
#
#    $self->init() unless $self->{s_box};
#
#    my $out = [];
#OUTER:
#    for my $row_num (0..$#$state) {
#        warn "LOOPING ROW [$row_num] IN STATE.";
#
#        for my $col_num (0..$#{ $state->[$row_num] }) {
#
#            my $b = $state->[$row_num][$col_num];
#            warn "GOT BYTE [" . sprintf("0x%x", $b) . "]";
#
#            my $inv = gf2_inv(8, $b);
#            warn "GOT INVERSE [" . sprintf("0x%x", $inv) . "]";
#
#            # transform to bit string
#            my $bit_str = unpack "B8", pack "C", $inv;
#            warn "GOT BIT STRING: [$bit_str]";
#            my @bits = split //, $bit_str;
#
#            my $byte = Math::FastGF2::Matrix->new(
#                rows    => 8,
#                cols    => 1,
#                width   => 1,
#            );
#
#            for my $i (0..$#bits) {
#                warn "- TO ROW [$i] ADD BIT [$bits[$i]]";
#                $byte->setval($i, 0, $bits[$i]);
#            }
#
#            # start affine transformation over GF(2)
#            # XXX: Something goes wrong here
#            my $trans_mat = $self->{sub_bytes_mul_mat}->multiply($byte);
#            warn "TRANSMAT ROWS: " . $trans_mat->ROWS;
#            warn "TRANSMAT COLS: " . $trans_mat->COLS;
#
#            # transfrom back to byte
#            my $trans_str = '';
#
#            for my $i (0..$trans_mat->ROWS - 1) {
#                my $bit = $trans_mat->getval($i, 0);
#                warn "ROW [$row_num], COL [$col_num] READ BIT [$bit]";
#                $trans_str .= $bit;
#            }
#
#            # we need to add [1, 1, 0, 0, 0, 1, 1, 0] to the transformation
#            # matrix. addition of polynomials in GF(2^n) is the same
#            # as XORing their byte representations
#            my $trans_byte = unpack "C", pack "B8", $trans_str;
#            my $add_byte   = unpack "C", pack "B8", "11000110";
#
#            my $final_byte = $trans_byte ^ $add_byte;
#            # end affine transformation over GF(2)
#
#            # lookup byte from SBOX, and that's our ret
#            #my $out_byte = $SBOX[$final_byte];
#            my $out_byte = $final_byte;
#            push @{ $out->[$row_num] }, $out_byte;
#
#            warn "GOT TRANS_STR [$trans_str], TRANS_BYTE [" . sprintf("0x%x", $trans_byte) . "], ADD_BYTE [" . sprintf("0x%x", $add_byte) ."]"
#                .", FINAL_BYTE [" . sprintf("0x%x", $final_byte) . "], OUT_BYTE [" . sprintf("0x%x", $out_byte) . "]";
#
#last OUTER;
#        }
#    }
#
#    return $out;
#}

1;


