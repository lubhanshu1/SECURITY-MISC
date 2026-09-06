#!/usr/bin/env perl

use strict;
use warnings;
use Digest::SHA qw(sha256_hex);

if (@ARGV != 1) {
    print "Usage: perl file_hash.pl <file>\n";
    exit 1;
}

my $file = $ARGV[0];

if (!-f $file) {
    print "Error: file not found: $file\n";
    exit 1;
}

open(my $fh, '<:raw', $file)
    or die "Error: cannot open file: $!\n";

my $sha = Digest::SHA->new(256);
$sha->addfile($fh);

close($fh);

print "File: $file\n";
print "SHA-256: ", $sha->hexdigest, "\n";