#! /usr/bin/perl
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

use strict;
use warnings;

# Required for threads
use 5.8.0;

#NOTE: Load these two early as possible and in this order.
use threads qw( yield );
use threads::shared;


###########
# Modules #
###########

# NOTE: Thread modules loaded at top of file. 
use Net::LDAP;
use Net::LDAP::Constant qw( LDAP_NO_SUCH_OBJECT );
use Getopt::Long;

use Treadmill::LDAP	qw( LDAP_Connect LDAP_Close LDAP_Fail_Msg );
use Treadmill::Config	qw( Load_Config :CONST);
use Treadmill::Testers	qw( Binder Searcher Adder Modifier Deleter );


#############
# Constants #
#############

# This represents how many ldap operations between thread->yield calls.
# NOTE: the time taken by each ldap op may be  *highly* variable. 
use constant OP_BLOCK_SIZE	=> 10;

# How many random characters to suffix new DNs with.
# You want it to be long enough to have a unique dn for each add.
# See $default_opts{randchars} for radix. 
use constant RAND_DATA_LEN	=> 32;

# This prepends new DNs. A Thread id is also suffixed later. 
use constant APP_NAME		=> 'Symas-Treadmill';

#Maximum number of threads we'll allow specified.
use constant MAX_THREADS	=> 16;


#########
# DEBUG #
#########

# Force print buffer to flush after each print if set. 
# Useful for debuging thread loops. 
$| = 1;


##################
# Thread sharing #
##################

# boolean to tell threads when it's time to clean up and shut down.
my $exit_threads :shared = 0;


##########
# CTRL-C #
##########

$SIG{'INT'} = \&Abort;


############
# Defaults #
############

my %options = (
	URI			=> 'ldap://localhost:389/',
	basedn		=> 'dc=example, dc=com',
	
	binddn		=> 'dc=example, dc=com',
	pass		=> 'secret',

	conffile	=> './treadmill.conf',
	profile		=> './profiles/basic',
	
	threads		=> 4,
	duration	=> 0,

	randchars	=> ['a'..'j'], 

	op_profile => {
					bind	=> 20,
					search	=> 20,
					add		=> 10,
					}
	);

# Fill in with key names that you wish to be required.
# If they are given real default values above this will not key. 
my @required_opts = qw( URI basedn threads randchars op_profile );


#########
# Usage #
#########

#TODO PerlDoc
my $usage = <<END;

treadmill.pl [-H ldapuri] [-D binddn] [-w passwd] [--help]
             [--threads num] [--config file] [--profile file]
             [--duration seconds]

* Single letter options mirror those of ldapsearch.

END


#############
# Call main #
#############

&main();


########
# Main #
########

sub main {
	my $thr_cnt;
	my $thr_msg_ref;
	my $dot_cnt; 
	#TODO: Re-add required opt checking. 
	
	my %shell_opts = &Get_Shell_Opts();
	&Hash_Overlay(\%options, \%shell_opts);
	
	&Get_File_Opts(\%options, $options{conffile});	
	&Hash_Overlay(\%options, \%shell_opts);
	
	&Get_Profile(\%options, $options{profile});
	&Hash_Overlay(\%options, \%shell_opts);

	my @config_errs = &Check_Opts(
								\%options, 
								\@required_opts);

	if (@config_errs) {
		print @config_errs;
		exit(1);
	}

	my ($i, $tmp_thr);
	for ($i = 0; $i < $options{threads}; $i++ ) {
		$tmp_thr = threads->create('Start_Thread', \%options);
	}

	print "Starting treadmill.\n";

	my $start = time();
	while (1) {	
		
		if ($options{duration} &&
			time() - $start >= $options{duration}) {		
			$exit_threads = 1;
		}

		print '.' unless ($exit_threads);
		print "\n" unless (++$dot_cnt % 60);

		($thr_cnt, $thr_msg_ref) = &Check_Threads();	
		last if (scalar(@{$thr_msg_ref}) || !$thr_cnt);
	
		sleep(1);
	}

	if (scalar(@{$thr_msg_ref})) {
		
		print "\n\nSome threads exited with errors:\n\n";
		print @{$thr_msg_ref};
		
		&Join_Threads;
		
		exit(1);
	}

	print "\nTest Completed.\n";
	exit(0);
}


#######################
# Thread related code #
#######################

sub Start_Thread {
	my %args = %{+shift};
	
	my ($ldap, $err_msg) = LDAP_Connect($args{URI}, $args{binddn}, $args{pass});
	return ($err_msg) if (defined($err_msg));

	my ($fun_refs, $arg_refs, $dns_ref) = Populate_Funs($args{op_profile}, \%args);
	
	my ($i, $fun_ret);
	my $cleanup_ret;
	while (1) {

		for($i=0; $i < scalar(@{$fun_refs}); $i++) {
		
			$fun_ret = $fun_refs->[$i]->($ldap, @{$arg_refs->[$i]});

			if ($fun_ret) {
				$cleanup_ret = &Cleanup($ldap, \%args, $dns_ref);
				
				return (LDAP_Fail_Msg($fun_ret), LDAP_Fail_Msg($cleanup_ret)) if ($cleanup_ret);
				return LDAP_Fail_Msg($fun_ret);
			} elsif ($exit_threads) {
				$cleanup_ret = &Cleanup($ldap, \%args, $dns_ref);
				
				return LDAP_Fail_Msg($cleanup_ret) if ($cleanup_ret);
				return 0;
			}

			threads->yield() unless ($i % OP_BLOCK_SIZE);
		}
	}
}


sub Check_Threads {
	my @returns = ();
	my $val;
	for my $thr (threads->list()) {
		unless ($thr->is_running()) {
			$val = $thr->join();
			push(@returns, $val) if (defined($val) && $val);
		}
	}

	# remove duplicate messages. 
	@returns = keys %{{ map { $_ => 1 } @returns }};


	return (scalar(threads->list()), \@returns);
}


sub Join_Threads {
	$exit_threads = 1;
	#NOTE: The threads->list(threads::joinable) list left over
	# threads leaving perl to squawk at the user. Bug?
	# perl -v = v5.10.1 (*) built for i486-linux-gnu-thread-multi
	for my $thr (threads->list()) {
		$thr->join();
	}
}


sub Abort {
	print "\nCaught CTRL-C. Performing Cleanup.\n";
	$exit_threads = 1;
}


#############
# Functions #
#############

sub Get_Shell_Opts {
	my %shell_opts;
	my $needs_help;
	
	Getopt::Long::Configure( qw( no_auto_abbrev no_ignore_case ) );

	GetOptions(
		'H=s'			=> \$shell_opts{URI},
		'D=s'			=> \$shell_opts{binddn},
		'w=s'			=> \$shell_opts{pass},
		'threads=i'		=> \$shell_opts{threads},
		'config=s'		=> \$shell_opts{conffile},
		'profile=s'		=> \$shell_opts{profile},
		'duration=i'	=> \$shell_opts{duration},
		'help|?'		=> \$needs_help,
		) or die ($usage);

	die($usage) if ($needs_help);
	
	#for (keys %shell_opts) {
	#	$opt_ref->{$_} = $shell_opts{$_};	
	#}
	
	return %shell_opts;
}


sub Get_File_Opts {
	my $opts_ref = shift;
	my $file = shift;	

	my ($config_ref, $err) = Load_Config($file);

	unless ($config_ref) {
		if ($err == CONFIG_ERR_NOEXIST) {
			print "Note: File not found:\n $file\n";
		} elsif ($err == CONFIG_ERR_NOREAD) {
			print "Note: The following file is not readable by effective user/group:\n $file\n";
		} elsif ($err == CONFIG_ERR_NOTFILE) {
			print "Note: The configuration file must be either a plain file or a symlink:\n $file\n";
		} elsif ($err == CONFIG_ERR_PARSE) {
			print "There was an error parsing the configuration file.\n $file\n";
			exit(1);
		}
		print "Proceeding with defaults and command line options.\n";
		return;
	}

	for (keys %{$config_ref}) {
		$opts_ref->{$_} = $config_ref->{$_}
	}

}


sub Get_Profile {
	&Get_File_Opts(@_);
}


sub Check_Opts {
	my %settings = %{+shift};
	my @reqs = @{+shift};
	my @errs;

	if ($settings{threads} > MAX_THREADS || $settings{threads} < 1) {
		push(@errs, "Allowed thread range is 1 to " . MAX_THREADS . "\n");
	}

	if ($settings{duration} < 0) {
		push(@errs, "Application Duration must be greater than or equal to zero.\n");
	}
	if (exists($settings{op_profile}{add}) && (@{$settings{randchars}} * RAND_DATA_LEN) < $settings{op_profile}{add}) {
		push(@errs, "The maximum number of add operations is " . (@{$settings{randchars}} * RAND_DATA_LEN). "\n");
	}
	
	for my $item (@reqs) {
		push (@errs, "Missing required option: $item \n") unless (exists($settings{$item}));
	}
	
	return @errs;
}


sub Cleanup {
	my $ldap = shift;
	my %settings = %{+shift};
	my @dns = @{+shift};
	my $msg;

	foreach my $dn (@dns) {
		$msg = $ldap->delete($dn);
		return $msg->code if ($msg->code && $msg->code != LDAP_NO_SUCH_OBJECT); 
	}
	
	LDAP_Close($ldap);
	return 0;
}


sub Populate_Funs {

	my %fun_types	= %{+shift};
	my %settings	= %{+shift};

	# TODO: Make these two configurable. 
	my $dn_attr		= 'cn';
	my @obj_class	= qw( top organizationalPerson );
	my @attr_list	= qw( cn sn title ou );

	my $prefix = APP_NAME . '-';
	# NOTE:tid is added as a suffix so that simple wildcard searches
	# can take advantage of the data from all threads.
	my $suffix = '-thread'. threads->self()->tid();
	
	my ( @bind_args, @add_args, @del_args, @search_args ) = ();
	my @dn_list;
	my @tmp_args;
	my ( $tmp_dn, $tmp_str );
	my %tmp_entry;

	my $i;

	# Set up our wild card searches. 
	my @search_chars = map($_ .'*', @{$settings{randchars}});
	push (@search_chars, '*');

	################################
	# Generate Operation Arguments #
	################################

	if (exists($fun_types{bind})) {
		for ($i=0; $i < $fun_types{bind}; $i++) {
			push(@bind_args, [$settings{binddn}, $settings{pass}]);
		}
	}	
	#NOTE: Both Add *and* delete args are set here. 
	if (exists($fun_types{add})) {
		for ($i=0; $i < $fun_types{add}; $i++) {
			$tmp_str	 = $prefix;
			$tmp_str	.= $settings{randchars}->[rand(@{$settings{randchars}})] for 1..RAND_DATA_LEN;
			$tmp_str	.= $suffix;
			$tmp_dn		 = "$dn_attr=$tmp_str, $settings{basedn}";
			
			if ( grep {$_->[0] eq $tmp_dn} @add_args){
				$i--;
				next;
			};

			%tmp_entry = (
				attrs	=> [
					objectClass	=> \@obj_class,
					$dn_attr	=> $tmp_str,
					sn			=> $tmp_str,
					title		=> $tmp_str,
					ou			=> $tmp_str,
				]
			);

			push(@add_args, [$tmp_dn, \%tmp_entry]);	
			push(@del_args, [$tmp_dn]);
			push(@dn_list, $tmp_dn);
			threads->yield();
		}	
	}
	

	if (exists($fun_types{search})) {
		for ($i=0; $i < $fun_types{search}; $i++) {
			
			$tmp_str  = '(' . $attr_list[rand(@attr_list)] . '=';
			$tmp_str .= $prefix; 
			$tmp_str .= $search_chars[rand(@search_chars)] . ')'; 
			push(@search_args, [$settings{basedn}, $tmp_str]);
		}
	}

	##################
	# Combine it all #
	##################

	my (@all_ops, @all_args); # the BIG ones
	my $op;
	my $new_adds= 0;
	my @op_list = keys(%fun_types);
	
	push(@op_list, 'del') if (exists($fun_types{'add'}));

	while(1) {
		$op = $op_list[rand(@op_list)];
		if ($op eq 'del') {
			unless ($new_adds) {
				$i--;
				next;
			}

			$new_adds--;
			
			push(@all_ops, \&Deleter);
			push(@all_args, pop(@del_args));
			
			@op_list = map { $_ eq 'del' ? () : $_} @op_list unless (@del_args);

		} elsif ($op eq 'add') {
		
			$new_adds++;
			
			push(@all_ops, \&Adder);
			push(@all_args, pop(@add_args));
			
			@op_list = map { $_ eq 'add' ? () : $_} @op_list unless (@add_args);

		} elsif ($op eq 'search') {
			push(@all_ops, \&Searcher);
			push(@all_args, pop(@search_args));
			# NOTE: This has potential for the same integration metioned in the bind note below.

			@op_list = map { $_ eq 'search' ? () : $_} @op_list unless (@search_args);

		} elsif ($op eq 'bind') {
			#NOTE: This logic can probibly encase the bind populator above...
			#      However, I want to keep the current model in the case above 
			#      code gets more complex. e.g. Binding different accounts.
			push(@all_ops, \&Binder);
			push(@all_args, pop(@bind_args));

			@op_list = map { $_ eq 'bind' ? () : $_} @op_list unless (@bind_args);
		
		}
	
		last unless(@op_list);
	}

	return \@all_ops, \@all_args, \@dn_list;
}

sub Hash_Overlay {
	my $src_ref = shift;
	my $overlay_ref = shift;

	my ($key, $value);
	while (($key, $value) = each %{$overlay_ref}) {
		next unless(defined($value));
		$src_ref->{$key} = $overlay_ref->{$key};
	}

}



