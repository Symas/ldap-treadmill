package LDAP;

use strict;
use warnings;


use Net::LDAP;
use Net::LDAP::Util qw( ldap_error_name dap_error_text ldap_error_desc );

require Exporter;
my $VERSION	= .1;
my @ISA		= qw( Exporter );

my @EXPORT_OK	= qw( LDAP_Connect LDAP_Close LDAP_Fail_Msg);
my %EXPORT_TAGS	= ();


#############
# Functions #
#############

=head1 FUNCTIONS
=cut

=head LDAP_Connect

 Purpose: Initialize our LDAP connection. 
 Accepts: Server URI,, Bind DN, Bind Pass
 Returns: An ldap connection object and a result code.

=cut

sub LDAP_Connect {

	my ( $server, $dn, $pass ) = @_;

	my $ldap;

	# Determine if we're using tls and connect appropriately
	if ( $server =~ m/^ldaps:\/\//i ) {
		
		$ldap = Net::LDAP->new($server);

		return (undef, $@) unless (defined($ldap));

		$ldap->start_tls();

	} elsif ( $server =~ m/^ldapi:\/\//i ) {
		$ldap = Net::LDAP->new($server);
	} else {
		$ldap = Net::LDAP->new($server);
	}

	return (undef, $@) unless (defined($ldap));

	if (defined($dn) && defined($pass)) {
		# Bind with credentials
		$ldap->bind(
		dn       => $dn,
		password => $pass);
	} else {
		# Bind anonymously
		$ldap->bind();
	}

	return $ldap, undef;
}


=head2 LDAP_Close

 Purpose: Close an LDAP conection
 Accepts: An LDAP connection
 Returns: Nothing

=cut

sub LDAP_Close {
	my $ldap = shift;
	$ldap->disconnect();
}

=head2 LDAP_Fail_Msg
 Purpose: Create an informative and verbose  error message from an LDAP error code.
 Accepts: LDAP error code
 Returns: Error string

=cut


sub LDAP_Fail_Msg {
	my $code = shift;

	my $str  = "The LDAP server returned an error:\n";
	my $str .= "\t Caller: " . caller() . "\n";
	my $str .= "\t Name: " . ldap_error_name($code) . "\n";
	my $str .= "\t Text: " . ldap_error_text($code) . "\n";
	my $str .= "\t Description: " . ldap_error_desc($code). "\n";

	return $str;
}




1;
