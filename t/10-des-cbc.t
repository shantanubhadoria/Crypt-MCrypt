use Test::Most 0.22;
use Crypt::MCrypt;

subtest "decryption using tripledes in cbc mode with nulls in iv" => sub {
    my $algorithm = "tripledes";
    my $mode = "cbc";
    my $iv = pack("H*","0000000000000000");
    my $key = pack("H*","1234567890123456" . "7890123456789012" . "1234567890123456");
    my $cipher_text = pack("H*","E9FF3161EE05ABC9" . "7ea3cacb991318aa" . "585379599b0eaabb" . "c4e474ead1956f47" . "6755f13f1af5235d");
    my $obj = Crypt::MCrypt->new(
        algorithm => $algorithm, 
        mode      => $mode,
        key       => $key, 
        iv        => $iv,
    );
    my $plain_text = $obj->decrypt($cipher_text);
    my $expected_plain_hex = "523130300039000630303030343700004700074d454654504f530048000931323334353637383900";
    is $plain_text, pack("H*",$expected_plain_hex),"decrypted plaintext matches expected plaintext";
};
done_testing;
