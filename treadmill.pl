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


=head1 NOTE

 For help on treadmill usage see `perldoc treadmill.pod`. This 
 file's documentation contains technical notes for programmers. 

=cut


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
use Net::LDAP::LDIF;
use Net::LDAP::Constant qw( LDAP_NO_SUCH_OBJECT LDAP_SIZELIMIT_EXCEEDED );

use Term::ReadKey qw( ReadMode ReadKey );
use Time::HiRes qw( usleep );
use List::Util qw( shuffle );

use Pod::Usage;
use Getopt::Long;

use Treadmill::LDAP		qw( LDAP_Connect LDAP_Close LDAP_Fail_Msg 
							LDIF_Open LDAP_Get_Set LDIF_Get_Set 
							LDIF_Close );
use Treadmill::Config	qw( Load_Config :CONST);
use Treadmill::Testers	qw( Binder Searcher Adder Modifier Deleter );

use POSIX;
use Term::Cap;


#############
# Constants #
#############

# How many ldap operations happen between thread->yield calls.
# NOTE: The time taken by each ldap op may be *highly* variable. 
use constant OP_BLOCK_SIZE	=> 10;

# How many random characters to suffix new DNs with.
# You want it to be long enough to have a unique DN for each add.
# See $default_opts{randchars} for radix. 
use constant RAND_DATA_LEN	=> 32;

# This prepends new DNs. A Thread id is also suffixed later. 
use constant APP_NAME		=> 'Symas-Treadmill';

# Maximum number of threads we'll allow specified.
use constant MAX_THREADS	=> 128;

# The number of starting characters for the search prefix stat.
# This may be converted into a search query depending on settings.
use constant STATS_DN_LEN	=> 1;

# Maximum number of entries to examine during stats generation.
# NOTE: For LDAP connections the server may have it's own configured 
#       limit. 
use constant STATS_MAX_CNT	=> 0;

# The number of entries to pull before processing that group
use constant STAT_SET_SIZE	=> 50;

# The maximum number threads to display. 
# NOTE: All cross-platform solutions for getting terminal height 
# require extra modules from CPAN.
use constant MAX_THR_ROWS	=> 35;

# Ignore Operation Failures.
use constant IGNORE_OP_FAIL	=> 1;

# How much to jump the throttle up/down(microseconds)?
use constant THR_THROTTLE_JMP	=> 100 * 1000;

#########
# DEBUG #
#########

# Forces print buffer to flush after each print if set. 
# Useful for debugging thread loops. 
$| = 1;

########
# Misc #
########

# Any extra mandatory cleanup.
END {
	ReadMode('restore');
}

##################
# Thread sharing #
##################

# When all elements are set to 1 we're ready start!
my @threads_ready :shared;

# Threads will wait for this one after their initialization.  
my $begin_threads :shared;

# boolean to tell threads when it's time to clean up and shut down.
my $exit_threads :shared = 0;

# Will hold an operation count for each thread. 
my %op_cnts :shared;

# shared variable for syncing throttle vals.
# TODO: There shoud be a shared hash and/or a shared array for all thread syncing.
my $thr_throttle :shared = 0;


############
# Defaults #
############
#NOTE: The settings merging function will go multiple levels through hash 
# but not array refs. This should probably change at some point.
my %options = (
	URI			=> 'ldap://localhost:389/',
	basedn		=> 'dc=example, dc=com',
	
	binddn		=> 'dc=example, dc=com',
	pass		=> 'secret',

	conffile	=> './treadmill.conf',
	profile		=> './profiles/basic',
	
	threads		=> 4,
	thr_throttle=> 0, # microseconds

	duration	=> 0,

	randchars	=> ['a'..'j'], 

	op_profile	=> {
					bind		=> 20,
					search		=> 20,
					add			=> 10,
					},

	op_args		=> {
					add => {dn_class => 'cn',},			
					},
	
	smartgen	=> {
					enabled		=> 0,
					searches	=> 1,
					binds		=> 1,
					},
	
	nostats		=> 0,
	);


# Fill in with key names that you wish to be required.
# If they are given real default values above this will not key. 
my @required_opts = qw( URI basedn threads thr_throttle randchars op_profile );

# List of hash methods supported by OpenLDAP.
# NOTE: Due to non-specific documentation these will be tested as case insensitive.
my @hash_methods = qw( CRYPT MD5 SMD5 SSHA SHA );

my %keys = (
	quit				=> 'q',
	thr_throttle_tog	=> 'p',
	thr_throttle_up		=> 'a',
	thr_throttle_down	=> 'z',
);



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
	my (@errs, $err);
	
	###################
	# Set up Term Cap #
	###################

	my $termios = new POSIX::Termios;
	$termios->getattr;
	my $terminal = Tgetent Term::Cap { 
			TERM => undef, 
			OSPEED => $termios->getospeed };
	$terminal->Trequire(qw( cl ce cm cd ti ));
	# NOTE: Not sure why but we segfault if we wait for perl to destroy
	# our termios object when the app quits. This line destroys it now. 
	# Upon further toying -- It appears that launching threads instigates
	# the issue...
	$termios = undef;

my $clear_line	= $terminal->Tputs('ce', 1, undef);
	my $term_home	= $terminal->Tgoto('cm', 0, 0, undef);

	print $terminal->Tputs('cl', 1, undef);

	#######################
	# Options and configs #
	#######################

	my %shell_opts = &Get_Shell_Opts();
	&Hash_Overlay(\%options, \%shell_opts);
	
	&Get_File_Opts(\%options, $options{conffile});	
	&Hash_Overlay(\%options, \%shell_opts);
	
	&Get_Profile(\%options, $options{profile});
	&Hash_Overlay(\%options, \%shell_opts);

	@errs = &Check_Opts(
						\%options, 
						\@required_opts);

	if (@errs) {
		print @errs;
		exit(1);
	}

	########
	# Misc #
	########
	my $status_height = 3;
	$status_height += 3 if $options{duration};
	$thr_throttle = $options{thr_throttle} * 1000;

	###################
	# LDAP/LDIF Stats #
	###################

	print "Initializing...\n";

	my ($stats_ref);
	if ($options{smartgen}{enabled}) {
		($stats_ref, $err) = Get_Stats(\%options);
		
		if ($err) {
			print $err;
			exit(1);
		}
	}


	######################################
	# First round of argument generation #
	######################################
	
	my $proto_args_ref = &Prep_Args(\%options, $stats_ref);
	

	##################
	# Tester Threads #
	##################

	my ($i, $tmp_thr);
	for ($i = 0; $i < $options{threads}; $i++ ) {
		$threads_ready[$i] = 0;
		$tmp_thr = threads->create('Start_Thread', \%options, $proto_args_ref);
	}
	
	# Wait for all the threads to initialize. 
	while(! $begin_threads) {
		$begin_threads = 1 unless (map {$_ == 0 ? 1 : ()} @threads_ready);	
		threads->yield();
	}

	
	# Begin trapping CTRL-C now..
	$SIG{'INT'} = \&Abort;

	# Set up key reading
	ReadMode('cbreak');

	print "Starting treadmill...\n";
	
	my $start = time();
	my (@last_cnts);
	my $status;
	my ($time_spent, $time_left);
	my $total_ops;
	my $throttle_store = undef;
	my $key = 0;
	while (1) {	
		$time_spent = time() - $start;			
		if ($options{duration} &&
			$time_spent >= $options{duration}) {		
			$exit_threads = 1;
		}

		# Handle key input
		$key = ReadKey(-1);
		if($key){
			if ($key eq $keys{thr_throttle_up}) {
				$thr_throttle += THR_THROTTLE_JMP;
			} elsif ($key eq $keys{thr_throttle_down}) {
				$thr_throttle -= THR_THROTTLE_JMP unless($thr_throttle == 0);
			} elsif ($key eq $keys{thr_throttle_tog}) {
				if (defined($throttle_store)){
					($thr_throttle, $throttle_store) = ($throttle_store, undef);
				} else {
					($thr_throttle, $throttle_store) = (0, $thr_throttle);
				}
			} elsif ($key eq $keys{quit}) {
				&Abort();
			}
			while (defined(ReadKey(-1))) {}; # Flush buffer
		}

		($thr_cnt, $thr_msg_ref) = &Check_Threads();	
		last if (scalar(@{$thr_msg_ref}) || !$thr_cnt);
		if (! $options{nostats}) {
			$time_left = ($options{duration}-(time()-$start));
			$time_left = 'Finishing...' if ($time_left <= 0);
			$status  = $term_home; 
			$status .= $clear_line . "Treadmill Running...\n";
			$status .= $clear_line . "Time Left: " . $time_left  . "\n" if ($options{duration});
			$status .= $clear_line . "Thread Pacing: " . ($thr_throttle ? $thr_throttle/1000 . "ms" : "Disabled" ) . "\n";
			$status .= $clear_line . "Keys:"
									." [Pace: $keys{thr_throttle_tog}|$keys{thr_throttle_up}|$keys{thr_throttle_down}]"
									." [Quit: $keys{quit}]"
									."\n";
			
			$status .= $clear_line . "\n";
			$status .= $clear_line . "\t\tAvg. Ops/s:\tTotal Ops:\n";
			$total_ops = 0;
			for ($i=1; $i <= keys(%op_cnts) && $i <= MAX_THR_ROWS; $i++) {
				$last_cnts[$i] = $op_cnts{$i};
				
				$status .= $clear_line . "Thread-$i\t"; 
				$status .= int($op_cnts{$i}/($time_spent+.5)) . "\t\t" . $op_cnts{$i} . "\n";
				$total_ops += $op_cnts{$i};
			}
			$status .= $clear_line . "\n";	
			$status .= $clear_line . "All threads\t". int($total_ops/($time_spent+.5)) . "\t\t"  . $total_ops;
	
			print $status;
	
		} else {
			print '.';
		}
		usleep(200_000); # 200ms
	
	}

	if (scalar(@{$thr_msg_ref})) {
		
		print "\n\nSome threads exited with errors:\n\n";
		print @{$thr_msg_ref};
		
		&Join_Threads;
		
		exit(1);
	}

	print "\n\nTest Completed.\n";
	exit(0);
}


=head1 FUNCTIONS

=cut


#######################
# Thread related code #
#######################

=head2 Start_Thread
 
 Purpose: Start a thread, generate a list of operations, and loop that list 
          until signaled to clean up and exit.
 Accepts: The treadmill configuration data structure. Some pre-genrated argument data.
          (See: Prep_Args)
 Returns: Zero on success. An error string on failure.  
 
=cut

sub Start_Thread {
	# These are sort of pseudo-references. Perl copies the data for each thread. 
	my %settings = %{+shift};
	my %proto_args = %{+shift};

	my $thread_id = threads->tid();

	my ($ldap, $err_msg) = LDAP_Connect($settings{URI}, $settings{binddn}, $settings{pass});
	return ($err_msg) if (defined($err_msg));

	my ($fun_refs, $arg_refs, $dns_ref) = Populate_Funs(\%settings, \%proto_args);

	# Signal readiness and hang out until the other threads are ready.
	$threads_ready[$thread_id-1] = 1;
	while (! $begin_threads){
		threads->yield();
	}

	my ($i, $fun_ret);
	my $cleanup_ret;
	while (1) {
		for($i=0; $i < scalar(@{$fun_refs}); $i++) {
			
			$op_cnts{$thread_id}++;

			$fun_ret = $fun_refs->[$i]->($ldap, @{$arg_refs->[$i]});

			if (! IGNORE_OP_FAIL && $fun_ret) {
				$cleanup_ret = &Cleanup($ldap, \%settings, $dns_ref);
				
				return (LDAP_Fail_Msg($fun_ret), LDAP_Fail_Msg($cleanup_ret)) if ($cleanup_ret);
				return LDAP_Fail_Msg($fun_ret);
			} elsif ($exit_threads) {
				$cleanup_ret = &Cleanup($ldap, \%settings, $dns_ref);
				
				return LDAP_Fail_Msg($cleanup_ret) if ($cleanup_ret);
				return 0;
			}
			
			threads->yield() unless ($i % OP_BLOCK_SIZE);
			usleep($thr_throttle);
		}
	}
}


=head2 Check_Threads
 
 Purpose: Make sure all our threads are still running. Join closed threads.
 Accepts: Nothing
 Returns: Number of remaining threads and an array ref containing thread return 
          values, if any. The array set is truncated for uniqueness. 

=cut

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


=head2 Join_Threads
 
 Purpose: Set the shared thread exit variable and block(via Join) while
          the threads perform cleanup and end.
 Accepts: Nothing
 Returns: Nothing

=cut

sub Join_Threads {
	$exit_threads = 1;
	#NOTE: The threads->list(threads::joinable) list left over
	# threads leaving perl to squawk at the user. Bug?
	# perl -v = v5.10.1 (*) built for i486-linux-gnu-thread-multi
	for my $thr (threads->list()) {
		$thr->join();
	}
}


=head2 Abort
 
 Purpose: Run after catching a CTRL-C to tell threads to close down.
 Accepts: Nothing
 Returns: Nothing

=cut

#NOTE: Why not call Join_Threads? 
sub Abort {
	print "\nAsked to quit. Performing Cleanup.\n";
	$exit_threads = 1;
}


=head2 Get_Shell_Opts
 
 Purpose: Generate a hash from command line options. Outputs usage 
          string and dies if asked for help.
 Accepts: Nothing
 Returns: A hash of selected shell options.
 
=cut

sub Get_Shell_Opts {
	my %shell_opts;
	my $needs_help;
	
	Getopt::Long::Configure( qw( no_auto_abbrev no_ignore_case ) );

	#TODO: Move to config section at beginning of file.
	GetOptions(
		'H=s'			=> \$shell_opts{URI},
		'D=s'			=> \$shell_opts{binddn},
		'w=s'			=> \$shell_opts{pass},
		'f=s'			=> \$shell_opts{ldiffile},
		'threads=i'		=> \$shell_opts{threads},
		'config=s'		=> \$shell_opts{conffile},
		'profile=s'		=> \$shell_opts{profile},
		'duration=i'	=> \$shell_opts{duration},
		'throttle=i'	=> \$shell_opts{thr_throttle},
		'smartgen'		=> \$shell_opts{smartgen}{enabled},
		'nostats'		=> \$shell_opts{nostats},
		'help|?'		=> \$needs_help,
		) or pod2usage(-input => './treadmill.pod');

	pod2usage(-input => './treadmill.pod') if ($needs_help);
	
	#for (keys %shell_opts) {
	#	$opt_ref->{$_} = $shell_opts{$_};	
	#}
	
	return %shell_opts;
}

=head2 Get_File_Opts 
 
 Purpose: Loads a configuration file. Used for config/profiles.
 Accepts: A reference to the current settings hash.
 Returns: Nothing

 Side effects: The new configuration variables are written to the 
               given settings hash.

=cut

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

	&Hash_Overlay($opts_ref, $config_ref);

}

=head2 Get_Profile
 
 Purpose: Alias to Get_File_Ops. Subject to future change. 

=cut

sub Get_Profile {
	&Get_File_Opts(@_);
}

=head2 Check_Opts
 
 Purpose: Do some basic checking on our input. 
 Accepts: A reference to the settings hash. A list of required keys.
 Returns: An array of error strings, if any. 

=cut

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

=head2 Cleanup
 
 Purpose: Delete any added DNs and close the LDAP connection. 
 Accepts: An LDAP connection, a settings hash ref, a list of DNs.
 Returns: Zero on success. An LDAP error code on failure.
 
=cut

sub Cleanup {
	my $ldap = shift;
	my %settings = %{+shift};
	my @dns = @{+shift};
	my $msg;
	
	# In case we're currently bound as someone else. 
	# We hit this one when both --duration and --smartgen are specified. 
	$msg = $ldap->bind($settings{binddn}, password => $settings{pass});
	return $msg->code if ($msg->code);

	foreach my $dn (@dns) {
		$msg = $ldap->delete($dn);
		return $msg->code if ($msg->code && $msg->code != LDAP_NO_SUCH_OBJECT); 
	}
	
	LDAP_Close($ldap);
	return 0;
}


=head2 Populate_Funs
 
 Purpose: To generate a somewhat randomized array of LDAP operation wrapper function 
          references and a corresponding array of parameters for each function.
 Accepts: A ref to the settings hash. A ref to a data structure containing some already 
          generated information. 
 Returns: Refs to arrays containing the function refs, the arg refs, and a list of DNs
          that will be used for adding entries. 

=cut

sub Populate_Funs {

	my %settings	= %{+shift};
	my %proto_args	= %{+shift};

	# TODO: Make these two configurable. (one down...) 
	my $dn_attr		= $settings{op_args}{add}{dn_class};
	my @obj_class	= qw( top organizationalPerson );
	
	my $rebind = [$settings{binddn}, $settings{pass}];

	# For add op DNs so threads don't clash. 
	my $suffix = threads->self()->tid();
	
	my (@add_args, @del_args) = ();
	my @dn_list;
	my ( $tmp_dn, $tmp_str );
	my %tmp_entry;
	
	my $i;
	
	
	#####################################
	# Generate More Operation Arguments #
	#####################################

	#NOTE: Both Add *and* delete args are set here. 
	if (exists($settings{op_profile}{add})) {
		for ($i=0; $i < $settings{op_profile}{add}; $i++) {
			$tmp_str	= $proto_args{add}->[$i] . $suffix;
			$tmp_dn		= "$dn_attr=$tmp_str, $settings{basedn}";

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
			threads->yield() unless ($i % OP_BLOCK_SIZE);
		}	
	}


	##################
	# Combine it all #
	##################
	
	my (@all_ops, @all_args); # the BIG ones
	my $op;
	my $lastop = '';
	my $new_adds = 0;
	my @op_list = keys(%{$settings{op_profile}});
	
	push(@op_list, 'del') if (exists($settings{op_profile}{'add'}));
	
	$i=0; 
	while(1) {
		$op = $op_list[rand(@op_list)];
		if ($lastop eq 'bind' && $op ne 'bind') {

			# Rebind as the privileged DN after one or more bind ops.
			# Needed since binds often share a connection with other ops. 
			push(@all_ops, \&Binder);
			push(@all_args, $rebind);
			
			# Drop one so counts are close to spec. Off by +1 may happen. 
			pop(@{$proto_args{bind}}) if (@{$proto_args{bind}});
			@op_list = map { $_ eq 'bind' ? () : $_} @op_list unless (@{$proto_args{bind}});
		
		} elsif ($op eq 'del') {

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
			push(@all_args, pop(@{$proto_args{search}}));

			@op_list = map { $_ eq 'search' ? () : $_} @op_list unless (@{$proto_args{search}});

		} elsif ($op eq 'bind') {
		
			push(@all_ops, \&Binder);
			push(@all_args, pop(@{$proto_args{bind}}));

			@op_list = map { $_ eq 'bind' ? () : $_} @op_list unless (@{$proto_args{bind}});
			
		}
	
		last unless(@op_list);
		
		$lastop = $op;

		threads->yield() unless ($i++ % OP_BLOCK_SIZE);
	}

	#DumpIt(\@all_args); exit(0);
	return \@all_ops, \@all_args, \@dn_list;
}

=head2 Hash_Overlay
 
 Purpose: Replace all values of one hash with those of another where they 
          exist and are not undef. Will deep copy through hash but not array refs.  
 Accepts: A source hash ref and a overlay hash ref.
 Returns: Nothing.

 Side Effects: Values in the source hash may be overwritten

=cut

sub Hash_Overlay {
	my $src_ref = shift;
	my $overlay_ref = shift;

 	my ($key, $value);
	while (($key, $value) = each %{$overlay_ref}) {
		
		next unless(defined($value));

		if (ref($value) eq 'HASH') {
			&Hash_Overlay($src_ref->{$key}, $overlay_ref->{$key});
		} else {
			$src_ref->{$key} = $overlay_ref->{$key};
		}
	}

}


=head2 Get_Stats
 
 Purpose: Gather some stats and information from an LDAP or LDIF source. 
 Accepts: A ref to the settings hash.
 Returns: A hash with aforementioned stats and info on success. undef and 
          an error message on failure.  

=cut

sub Get_Stats {
	my %settings = %{+shift};
	my $useldif = exists($settings{ldiffile}) ? 1 : 0;
	my %entry_stats;
	my ($err, $err_msg);

	
	my ($ldif);
	my ($ldap, $search);
	if ($useldif) {

		($ldif, $err) = LDIF_Open($settings{ldiffile});
		
		return undef, LDIF_Err_Text($err) if $err;
		
	} else {
		($ldap, $err) = LDAP_Connect($settings{URI}, $settings{binddn}, $settings{pass});

		return undef, $err if ($err);
		
		$search = $ldap->search(
			base		=> $settings{basedn},
			filter		=> '(objectclass=*)',
			sizelimit	=> STATS_MAX_CNT,
			);

		# NOTE: LDAP_SIZELIMIT_EXCEEDED just means there are more 
		# entries available than we asked for. 
		if ($search->code() && $search->code() != LDAP_SIZELIMIT_EXCEEDED){
			return undef, LDAP_Fail_Msg($search->code(), 1)
		}
	}
	

	my $entry;
	my $entry_list_ref;
	my ($tmp_dn, $dn_attr, $dn_attr_vali, $cut_dn);
	my ($cred_cnt);
	my $tmp_pass;
	my @bind_info;
	while(1) {
		if ($ldif) { 
			($entry_list_ref, $err) = LDIF_Get_Set($ldif, STAT_SET_SIZE);
		} else {
			($entry_list_ref, $err) = LDAP_Get_Set($search, STAT_SET_SIZE);
		}
	
		return undef, $err if ($err);

		last unless(@{$entry_list_ref});
		
		# Build up some info that may be useful to op generation.
		foreach $entry (@{$entry_list_ref}) {
			
			# Number of entries queried
			last if (STATS_MAX_CNT && $entry_stats{cnt} == STATS_MAX_CNT);
			$entry_stats{cnt}++;


			# Count up total instances of attributes.. 
			map {$entry_stats{attr_cnts}{$_}++} ${$entry}->attributes;


			# Search strings via DN cutting
			$tmp_dn 		= ${$entry}->dn();
			$cut_dn = substr($tmp_dn, 0, index($tmp_dn, '=') + STATS_DN_LEN + 1);
			$entry_stats{dn_cut_cnts}{$cut_dn}++;


			# Accounts for Binds	
			if ($settings{smartgen}{binds} &&
				exists($settings{op_profile}{bind}) &&
				${$entry}->exists('userPassword')) {
			
				if ($cred_cnt++ < $settings{op_profile}{bind}){

					# NOTE: Net::LDAP does our base64 decoding for us. :-)
					$tmp_pass = ${$entry}->get_value('userPassword');
					
					unless (
						($tmp_pass =~ /^\{([a-z\-0-9]+?)\}/i && grep(/^$1$/i, @hash_methods))
						|| ($tmp_pass =~ /^\{(x\-.+?)\}/i)) {
						
						push(@bind_info,[${$entry}->dn, $tmp_pass]);
					}
				}
			}


		} # End entry subset loop

	} # End all entry loop

	$entry_stats{bind_creds} = \@bind_info if (@bind_info);

	LDAP_Close($ldap) if ($ldap);
	LDIF_Close($ldif) if ($ldif);

	return \%entry_stats, undef;
}



=head2 Prep_Args

 Purpose: Generate as much thread-indifferent op argument data as possible.
 Accepts: A reference to the settings hash. A reference to the result of 
          &Get_Stats
 Returns: A Data structure containing full or partial arguments for op
          functions.

=cut

sub Prep_Args {
	my $opt_ref = shift;
	my $stats_ref = shift;
	my $dn_ojc = $opt_ref->{op_args}{add}{dn_class}; 
	
	my %proto_args;
	
	# drop any 0 op sets. 
	map { delete($opt_ref->{op_profile}{$_}) unless $opt_ref->{op_profile}{$_}} keys(%{$opt_ref->{op_profile}});

	# Search Args
	if (exists($opt_ref->{op_profile}{search})) {
	
		my (@search_vals, @search_args);
		if (exists($stats_ref->{dn_cut_cnts})) {
				
			my $srch_cnt;
			foreach ( 
				sort {$stats_ref->{dn_cut_cnts}{$b} <=> $stats_ref->{dn_cut_cnts}{$a}} 
				(keys %{$stats_ref->{dn_cut_cnts}})) {
				
				push(@search_vals,  "($_*)");
				last if (++$srch_cnt == $opt_ref->{op_profile}{search}-1);
			}

		} else {
			@search_vals = map {"($dn_ojc=$_*)"} @{$opt_ref->{randchars}};
			push(@search_vals, "($dn_ojc=*)");
		}
				
		push(@search_vals, '(objectClass=*)');
		@search_vals = shuffle(@search_vals);
		
		for(my $i=0; $i < $opt_ref->{op_profile}{search}; $i++){
			push(@search_args, [$opt_ref->{basedn}, @search_vals[rand(@search_vals)]]);
		}

		$proto_args{search} = \@search_args;
	}


	# Bind Args
	if (exists($opt_ref->{op_profile}{bind})) {
		if (exists($stats_ref->{bind_creds})) {
			$proto_args{bind} = $stats_ref->{bind_creds};		
		} else {
			my @bind_arr;
			push(@bind_arr, [$opt_ref->{binddn}, $opt_ref->{pass}]) for 1..$opt_ref->{op_profile}{bind};
			$proto_args{bind} = \@bind_arr;
		}
	}


	# Add Set. 
	# This is the most incomplete arg initialization. Since each thread will 
	# want to add a unique identifier to Add DNs. 
	if (exists($opt_ref->{op_profile}{add})) {
		# NOTE: Consider that this could just be incrementing numbers.
		my $tmp_adds_ref = &Rand_Arr(
				$opt_ref->{randchars},
				$opt_ref->{op_profile}{add},  
				RAND_DATA_LEN);
		
		map {$_ = APP_NAME . "-$_-thread"} @{$tmp_adds_ref};

		$proto_args{add} = $tmp_adds_ref;
	}
	
	return \%proto_args;
}


=head2 Rand_Arr

 Purpose: Populate an array with random characters. Uniqueness between entries
          is enforced. WARNING: An infinate loop is possible if set doesn't allow 
          enough potential matches to cover $arr_len.
 Accepts: A character set(array ref), an array length, and a string length
 Returns: A reference to the array.

=cut

sub Rand_Arr {
	my @set		= @{+shift};
	my $arr_len	= shift;
	my $str_len	= shift;
	my $str;
	my @arr;

	while($arr_len--) {
		$str = '';
		$str .= $set[rand(@set)] for 1..$str_len;

		if (grep {$_ eq $str} @arr) {
			$arr_len++;
			next;
		}
		
		push(@arr, $str); 
	}

	return \@arr;
}


###################
# Debug Functions #
###################

=head2 DumpIt
 
 Purpose: A debug function that loads, at runtime, the Data::Dumper module and 
          uses it to print the contents of the given argument.
 Accepts: A scalar to be passed to Dumper(). May be a reference to other data types. 
 Returns: Nothing. 

=cut

sub DumpIt {
	require Data::Dumper;
	import Data::Dumper;
	print Dumper(shift);
}

=head2 SysLog

 Purpose: Log a single message to the syslog. Loads modules at runtime.
 Accepts: A message string.
 Returns: Nothing.

=cut

sub SysLogIt {
	require Sys::Syslog;
	import Sys::Syslog;

	openlog($0, 'user');
	syslog('info', scalar(shift));
	closelog();

}



##########################
#           END          #
##########################

