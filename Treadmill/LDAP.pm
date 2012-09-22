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

package Treadmill::LDAP;

use strict;
use warnings;


use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Util qw( ldap_error_name ldap_error_text ldap_error_desc );

require Exporter;

our $VERSION		= 0.2;
our @ISA			= qw( Exporter );

our @EXPORT_OK		= qw( LDAP_Connect LDAP_Close LDAP_Fail_Msg LDIF_Open 
						LDAP_Get_Set LDIF_Get_Set LDIF_Close LDIF_Err_Text );
#our %EXPORT_TAGS	= ();

#############
# Constants #
#############

use constant LDIF_SUCCESS     => 0;

use constant LDIF_ERR_NOEXIST	=> 1;
use constant LDIF_ERR_NOREAD	=> 2;
use constant LDIF_ERR_PARSE		=> 3;
use constant LDIF_ERR_NOTFILE	=> 4;
use constant LDIF_ERR_OPEN		=> 5;

#########
# Other #
#########

my %LDIF_Err_Msgs = (
	LDIF_ERR_NOEXIST	=> 'The specified LDIF file does not exist.',
	LDIF_ERR_NOREAD		=> 'The specified LDIF file is not readable.',
	LDIF_ERR_PARSE		=> 'There was an issue parsing the LDIF file.',
	LDIF_ERR_NOTFILE	=> 'The path specified does not point to a file.',
	LDIF_ERR_OPEN		=> 'There was an error opening the specified LDIF file',
);


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

	# Determine if we're using TLS and connect appropriately
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


=head2 LDAP_Get_Set

Purpose: Get N Net::LDAP::Entry objects and return them in an array.
 Accepts: Net::LDAP::Search object and a count.
 Returns: An array of references or undef if empty

 Note: This subroutine will block while new entries come in from LDAP.
 Should not be terrible most of the time, though, since openldap is 
 much faster than perl. 

=cut

sub LDAP_Get_Set {
	my $search = shift;
	my $count = shift;
	my @arr;
	
	my $entry_ref;
	while ($count--) {
		$entry_ref = \$search->shift_entry();
		last unless (defined(${$entry_ref}));
		push(@arr, $entry_ref);
	}
	return \@arr, undef;
}

=head2 LDIF_Open

Purpose: Open an ldif file and returnan ldif object. 
 Accepts: The LDIF file location.
 Returns: An ldif object of undef & an error code.

=cut

#TODO: TEST
sub LDIF_Open {
	my $file = shift;
	return undef, LDIF_ERR_NOEXIST    unless (-e $file);
	return undef, LDIF_ERR_NOREAD     unless (-r $file);
	return undef, LDIF_ERR_NOTFILE    unless (-f $file || -l $file);

	my $ldif = Net::LDAP::LDIF->new($file, 'r', onerror => undef, wrap => 0);

	return undef, LDIF_ERR_OPEN unless (defined($ldif));
	
	return $ldif, LDIF_SUCCESS;
}


=head2 LDIF_Get_Set 

 Purpose: Get N Net::LDAP::Entry objects and return them in an array.
 Accepts: An LDIF object and a count.
 Returns: An array of references or undef if empty.

=cut

#TODO: TEST
sub LDIF_Get_Set {
	my $ldif = shift;
	my $count = shift;
	my @arr = ();
	my $err;

	my $entry_ref;
	while ($count-- && !$ldif->eof()) {
		$entry_ref = \$ldif->read_entry();
		unless (${$entry_ref}) {
			$err  = "\nLDIF error: ";
			$err .= $ldif->error() . "\n";
			$err .= "Halted on following text:\n\n";
			$err .= $ldif->error_lines ."\n\n";

			return undef, $err;
			#die("\n" . $ldif->error . "\nLines: " . $ldif->error_lines . "\n\n");
		}

		push(@arr, $entry_ref);

	}

	return \@arr, undef;
}


=head2 LDIF_Close

 Purpose: Close an LDAP conection
 Accepts: An LDAP connection
 Returns: Nothing

=cut
 
sub LDIF_Close {
	my $ldif = shift;
	$ldif->done();
}


=head2 LDIF_Err_Text

 Purpose: Retrieve a generic error message for a given treadmill LDIF file 
          error code. 
 Accepts: An error code.
 Returns: A string description. undef on failure. 

=cut

sub LDIF_err_Text {
	my $err = shift;
	return $LDIF_Err_Msgs{$err} if (exists($LDIF_Err_Msgs{$err}));
	return undef;
}



1;
