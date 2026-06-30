#!perl

use v5.10;
use Test::More;

use CVSS qw();

# functional API
for my $f (qw(encode_cvss decode_cvss cvss_to_xml)) {
    can_ok('CVSS',$f);
}
# OO API
for my $f (qw(new from_vector_string)) {
    can_ok('CVSS',$f);
}

# For each Class or Object ...
my $cvssv2  = CVSS->new(version => '2.0');
my $cvssv30 = CVSS->new(version => '3.0');
my $cvssv31 = CVSS->new(version => '3.1');
my $cvssv4  = CVSS->new(version => '4.0');
for my $clob (qw(CVSS::v2 CVSS::v3 CVSS::v4), $cvssv2, $cvssv30, $cvssv31, $cvssv4) {

    # OO API
    for my $f (qw(new from_vector_string)) {
        can_ok($clob,$f);
    }

    # Inherited from Base.pm
    for my $f (qw( version vector_string metrics scores calculate_score
        score_to_severity base_score temporal_score temporal_severity
        environmental_score environmental_severity impact_score
        exploitability_score modified_impact_score)) {
        can_ok($clob,$f);
    }

    # Generic metrics
    for my $f (qw(M metric)) {
        can_ok($clob,$f);
    }

    # Data Representations
    for my $f (qw(to_vector_string to_xml TO_JSON)) {
        can_ok($clob,$f);
    }

    # Constants
    for my $f (qw(ATTRIBUTES METRIC_GROUPS METRIC_NAMES
        METRIC_VALUES NOT_DEFINED_VALUE SCORE_SEVERITY
        VECTOR_STRING_REGEX)) {
        can_ok($clob,$f);
    }

    # Metric accessors - sort to keep tests in deterministic order
    for my $long (sort keys %{$clob->ATTRIBUTES}) {
        can_ok($clob,$long);
        can_ok($clob,$clob->ATTRIBUTES->{$long});
    }

}

done_testing();

