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
package LDAP;

use strict;
use warnings;


use Net::LDAP;
use Net::LDAP::Util qw( ldap_error_name ldap_error_text ldap_error_desc );

require Exporter;

our $VERSION		= .1;
our @ISA			= qw( Exporter );

our @EXPORT_OK		= qw( LDAP_Connect LDAP_Close LDAP_Fail_Msg);
#our %EXPORT_TAGS	= ();


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
	my $msg;	

	# Determine if we're using tls and connect appropriately
	if ( $server =~ m/^ldaps:\/\//i ) {

		# test for required modules
		unless ( eval "use IO::Socket::SSL" ) {
			return $ldap, "LDAPS required IO::Socket::SSL";
		}
		
		$ldap = Net::LDAP->new($server);

		return ($ldap, $@) unless (defined($ldap));

		$ldap->start_tls();

	} elsif ( $server =~ m/^ldapi:\/\//i ) {
		$ldap = Net::LDAP->new($server);
	} else {
		$ldap = Net::LDAP->new($server);
	}

	return ($ldap, $@) unless (defined($ldap));

	if (defined($dn) && defined($pass)) {
		
		$msg = $ldap->bind(
		dn       => $dn,
		password => $pass);
	} else {
		# Bind anonymously
		$ldap->bind();
	}

	return $ldap, LDAP_Fail_Msg($msg->code(), 1) if($msg->code());

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
 	my $short = shift;

	my $str;
	unless ($short) {
		$str .= "The LDAP server returned an error:\n";
		#$str	.= "Caller: " . caller() . "\n";
		$str .= "Name: " . ldap_error_name($code) . "\n";
	}

	$str .= "Description: " . ldap_error_desc($code) . "\n";
	$str .= "Text: " . ldap_error_text($code) . "\n";

	return $str;
}




1;
