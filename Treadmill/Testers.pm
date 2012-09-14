# -----------------------------------------------------------------------
#                        SYMAS OPEN SOURCE LICENSE
# 
# Copyright (c) 2008, 2009, 2010, 2011, 2012 Symas Corporation
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of the Symas Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# -----------------------------------------------------------------------
package Treadmill::Testers;

use strict;
use warnings;

use Net::LDAP;


require Exporter;

our $VERSION	= 0.1;
our @ISA		= qw( Exporter );

our @EXPORT_OK	= qw( Binder Searcher Adder Modifier Deleter );



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

	#print "Binding as: \"$dn\" \"$pw\"";
	
	my $msg = $ldap->bind( $dn, password => $pw );
	return $msg->code();
}


=head1 Searcher
 Purpose: Runs a search on an ldap server
 Accepts: LDAP Connection, Filter String
 Returns: A Net::LDAP::Message code. ( 0 for success )

=cut

sub Searcher {
	my ($ldap,$base, $filter) = @_;

	my $search = $ldap->search( base => $base, filter => $filter );

	#print "Searched for: $filter\t\t" . $search->count() . "\n";	

	return $search->code;
}


=head1 Adder
 Purpose: Add some data to LDAP
 Accepts: LDAP Connection, DN, Attr hash ref. 
 Returns: A Net::LDAP::Message code. ( 0 for success )

=cut

sub Adder {
	my ( $ldap, $dn, $attr_ref ) = @_;
	
	#print "Adding: $dn\n";
	
	my $msg = $ldap->add( $dn, %{$attr_ref} );	
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

	#print "Deleting: $dn\n";
	my $mesg = $ldap->delete($dn);
	return $mesg->code();
}

1;
