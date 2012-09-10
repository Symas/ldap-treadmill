package Testers;

use strict;
use warnings;

use Net::LDAP;


require Exporter;
my @ISA			= qw( Exporter );
my @EXPORT_OK	= qw( Binder Searcher Adder Modifier Deleter );



#############
# Functions #
#############

=head1 Binder
 Purpose: Unbinds and re-binds inside an ldap session
 Accepts: LDAP Connection, Bind DN, Bind Pass
 Returns: A Net::LDAP::Message code. ( 0 for success )

=cut

sub Binder {
	my ($ldap, $dn, $pw) =  @_;

	$ldap->unbind();

	my $msg = $ldap->bind( $dn, password =>$pw );
	return $msg->code();
}


=head1 Searcher
 Purpose: Runs a search on an ldap server
 Accepts: LDAP Connection, Filter String
 Returns: A Net::LDAP::Message code. ( 0 for success )

=cut

sub Searcher {
	my ($ldap, $filter) = @_;

	my $msg = $ldap->search( filter => $filter );
	return $msg->code
}


=head1 Adder
 Purpose: Add some data to LDAP
 Accepts: LDAP Connection, DN, Attr hash ref. 
 Returns: A Net::LDAP::Message code. ( 0 for success )

=cut

sub Adder() {
	my ( $ldap, $dn, $attr_ref ) = @_;

	my $msg = $ldap->add( $dn, $attr_ref );	
	return $msg->code();
}


=head1 Modifier
 Purpose: Replace the contents of a LDAP attribute.
 Accepts: LDAP Connection, DN, a hash of new data. 

=cut

sub Modifier {
	my ( $ldap, $dn, $attr_ref ) = @_;

	#TODO: add more operation types. See perldoc for modify...
	my $mesg = $ldap->modify($dn, replace => $attr_ref);
	return $mesg->code();
}


=head1 Deleter
 Purpose: Delete an entry
 Accepts: LDAP Connection, DN
 Returns: Returns: A Net::LDAP::Message code. ( 0 for success )

=cut

sub Deleter {
	my ($ldap, $dn) = @_;

	my $mesg = $ldap->delete($dn);
	return $mesg->code();
}

1;
