#!/usr/local/bin/perl
use strict;
use Digest::HMAC_SHA1;
use URI;

die "$0 <url> <AccessKey> <Secret> [Expires]\n" if @ARGV < 3;
my( $url, $access_key, $secret, $exp ) = @ARGV;
$exp ||= 300; # 5min
$exp += time;

my $uri = URI->new( $url );
my $plain = sprintf '%s%s%s%s', 'GET', $uri->path, $exp, $access_key;
my $hmac = Digest::HMAC_SHA1->new( $secret );
$hmac->add( $plain );
my $sig = $hmac->b64digest;
$uri->query_form({
    Signature => $sig,
    AccessKey => $access_key,
    Expires => $exp,
});
print $uri->as_string, "\n";
