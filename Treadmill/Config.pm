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
package Treadmill::Config;

use strict;
use warnings;

use Safe;

require Exporter;

our $VERSION	= .1;
our @ISA		= qw( Exporter );

our @EXPORT_OK	 = qw( Load_Config );
our %EXPORT_TAGS = (
					CONST => [qw( CONFIG_SUCCESS CONFIG_ERR_NOEXIST 
					              CONFIG_ERR_NOREAD CONFIG_ERR_PARSE 
					              CONFIG_ERR_NOTFILE )],
					);

Exporter::export_ok_tags('CONST');


=head1 Load_Config

Purpose: To load a perl format configuration file.
Accepts: File name
Returns: 
	* A hash datastructure on success.
	* undef and an error code on failure. 
=cut

use constant CONFIG_SUCCESS		=> 0;

use constant CONFIG_ERR_NOEXIST	=> 1;
use constant CONFIG_ERR_NOREAD	=> 2;
use constant CONFIG_ERR_PARSE	=> 3;
use constant CONFIG_ERR_NOTFILE	=> 4;

our %Options;

sub Load_Config {
	my $file = shift;

	return undef, CONFIG_ERR_NOEXIST	unless (-e $file);
	return undef, CONFIG_ERR_NOREAD		unless (-r $file);
	return undef, CONFIG_ERR_NOTFILE	unless (-f $file || -l $file);

	my $compartment = new Safe;
	$compartment->share('%Options');
	$compartment->permit_only(qw( padany refgen :base_core :base_mem :base_math ));
	my $result = $compartment->rdo($file,1);

	if ($@) {
		# For an opcode/description table see `perl -MOpcode=opdump -e opdump`
		# You can use the error information in $@ to match a description to a code 
		# and add it above.
		# print "\n $@\n";
		return undef, CONFIG_ERR_PARSE;
	};
	
	return \%Options, undef;
}

1;
