package Crypt::MCrypt;

# PODNAME: Crypt::MCrypt
# ABSTRACT: Perl interface for libmcrypt C library.  
# COPYRIGHT
# VERSION

use 5.014002;

# Dependencies
use Mo;
use Carp;


our $VERSION = '0.01';
require XSLoader;
XSLoader::load('Crypt::MCrypt', $VERSION);

=encoding utf-8

=attr algorithm

contains the name of the algorithm used to decrypt encrypt blocks of data

=cut

has algorithm => ();

=attr mode 

contains the name of the L<block cipher mode of operation|http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation> used to encrypt/decrypt blocks of data.

=cut

has mode => ();

=attr key

contains the key for the encryption decryption algorithm

=cut 

has key => ();

=attr Initialization Vector 

contains the Initialization for the first block of data in block cipher mode of operation. 

=cut 

has iv => ();

=method $self->decrypt($ciphertext)

decrypt blocks of ciphertext 

=cut

sub decrypt {
    my ($self,$ciphertext) = @_;

    my $length = length($ciphertext);
    my $plain_hex = Crypt::MCrypt::_decrypt($self->algorithm,$self->mode,$ciphertext,$self->key,$length,$self->iv);
    return pack("H*",$plain_hex);
}

=method $self->encrypt($ciphertext)

encrypt blocks of data

=cut

sub encrypt {
    my ($self,$plaintext) = @_;

    my $length = length($plaintext);
    my $cipher_hex = Crypt::MCrypt::_encrypt($self->algorithm,$self->mode,$plaintext,$self->key,$length,$self->iv);
    return pack("H*",$cipher_hex);
}

1;

__END__

=begin wikidoc

= SYNOPSIS

    use Crypt::MCrypt;

    my $iv = pack("H*","0000000000000000");
    my $key = pack("H*","1234567890123456" . "7890123456789012" . "1234567890123456");
    my $cipher_text = pack("H*","E9FF3161EE05ABC9" 
        . "7ea3cacb991318aa" 
        . "585379599b0eaabb" 
        . "c4e474ead1956f47" 
        . "6755f13f1af5235d");
    my $algorithm = "tripledes";
    my $mode = "cbc";
    my $obj = Crypt::MCrypt->new(
        algorithm => $algorithm, 
        mode      => $mode,
        key       => $key, 
        iv        => $iv,
    );
    my $plain_text = $obj->decrypt($cipher_text);
    print "\nPLAIN: $plain_text\n";
    print "\nPLAIN in hex: " . unpack("H*",$plain_text) . "\n";
    $cipher_text = $obj->encrypt($plain_text);
    print "\nCIPHER: $cipher_text\n";
    print "\nCIPHER in hex: " . unpack("H*",$cipher_text) . "\n";

= DESCRIPTION

This is a perl interface to libmcrypt c library. It exposes the crypto functions provided by the libmcrypt library in a perl interface 
with a binding code that accoutns for null C strings in ciphertext or plain text.

= USAGE

* This module provides a oibject oriented interface to the libmcrypt library. It uses Mo, a scaled down version of Moose without any data checks to improve speed.

= see ALSO

* [Mo]

=end wikidoc

=cut
