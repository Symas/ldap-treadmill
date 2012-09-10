#! /usr/bin/perl -w

use strict;
use warnings;

# Required for threads
use 5.10.0;

#NOTE: Docs say keep these in this order and at the top. 
use threads qw( yield );
use threads::shared;

use Net::LDAP;
#use Net::LDAP::Util qw( ldap_error_name ldap_error_text ldap_error_desc ); 
use Getopt::Long;


use LDAP	qw( LDAP_Connect LDAP_Close LDAP_Fail_Msg );
#use Config	qw( Load_Config );
use Testers	qw( Binder Searcher Adder Modifier Deleter );

#############
# Constants #
#############

# This represents how many ldap operations between thread->yield calls.
# NOTE: the time taken by each ldap op may be  *highly* variable. 
use constant OP_BLOCK_SIZE	=> 6;


############
# Defaults #
############

my %default_opts = {
	URI			=> 'localhost',
	port		=> 389,
	basedn		=> 'dc=example, dc=com',
	
	binddn		=> undef,
	pass		=> undef,

	conffile	=> './treadmill.conf',
	profile		=> './profiles/basic',
	
	threads		=> 4,
	duration	=> 30,
	opcount		=> 0; # determined programaticly

	};

# Fill in with key names that you wish to be required.
# If they are given real default values above this will not key. 
my @required_opts = ();

# these values represent the type and percent of operations.
my %op_types = {
	bind	=> 20,
	search	=> 40,
	add		=> 30,
	del		=> 10,
	};




#########
# Usage #
#########

# TODO
my $usage = <<END;

./treadmill.pl []

END


########
# Main #
########

sub main {
	my %settings = ParseOpts(\%default_opts, \@required_opts);	

	foreach $key (keys @op_types) {
		$settings{opcount} = $settings{opcount} + $op_types{$key};
	}

	# Set up our threads
	my ($i, $tmp_thr);
	for ($i = 0; $i < $settings{threads}; $i++ ) {
		$tmp_thr = threads->create('start_thread', \%settings);
	}

	print "Starting treadmill.\n";
	print "Running";

	# Main loop
	my $start= time();
	while (1) {
		for my $thr (threads->list(threads::all)) {
			die ($thr->error()) unless ( $thr->is_running() || $thr->error() );
		}
		sleep(1);
		break if (time() - $start >= $settings{duration});
		print '.';
	}

	print "Test Completed.\n";
	exit(0);
}


###############
# Thread code #
###############

sub start_thread {
	my %args = %{+shift};

	my ($ldap, $err_msg) = LDAP_Connect($args{URI}, $args{port});

	if (defined($err_msg)) die("\nCan't Connect to server: $err_msg\n");
	
	my ($fun_refs, $arg_refs) = Populate_Funs(\%op_types, \%args);

	my ($i, $fun_ret);
	while (1) {
		for($i=0; $i < $args{opcount}; $i++) {

			$fun_ret = $fun_refs->[$i]->($arg_refs->[$i]);

			if ($fun_ret) {
				$ldap->close();
				return $fun_ret;
			}

			threads->yield() unless ($i % OP_BLOCK_SIZE);
		}
	}

	return 0;
}



#############
# Functions #
#############

sub ParseOpts {
	my %defaults = %{+shift};
	my @reqs = @{+shift};
	
	my $needs_help;

	GetOptions(
		'H=s'			=> \$defaults{URI},
		'p=i'			=> \$defaults{port},
		'w=s'			=> \$defaults{pass},
		'threads=i'i	=> \$defaults{threads},
		'conf=s'		=> \$defaults{conffile},
		'profile=s'		=> \$defaults{profile},
		'duration=i'	=> \$defaults{duration},
		'help|?|h'		=> $needs_help,
		) or die ($usage);

	die($usage) if ($needs_help);


	for my $item (@reqs) {
		die($usage) if (!exists($defaults{$item}) || $defaults{$item} == undef);
	}

	return %defaults;
}


sub Populate_Funs {
	my %fun_types	= %{+shift};
	my %settings	= %{+shift};

	#TODO: Make these two configurable. 
	my $dn_attr = 'cn';
	my @attr_list = qw( cn sn title ou );

	my ( @bind_args, @add_args, @del_args, @search_args ) = ();
	my @tmp_args;
	my ( $tmp_dn, $tmp_str );
	my %tmp_entry;

	my $i;

	my @chars = ( "a".."z" , "A".."Z", 0..9 );
	my $del_counter = exists($fun_types{del}) ? $fun_types{del} : 0;


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
			
			$tmp_str .= $chars[rand(@chars)] for 1..10;
			$tmp_dn = "$dn_attr=$tmp_str, $settings{binddn}";
			
			%tmp_entry = {
				$dn_attr	=> $tmp_str,
				sn			=> $tmp_str,
				title		=> $tmp_str,
				ou			=> $tmp_str,	
			};

			push(@add_args, [$tmp_dn, \%tmp_entry]);

			# save some to delete later.
			unless ($del_counter == 0) {
				push(@del_args, $tmp_dn);
				$del_counter--;
			}
			
		}	
	}

	if (exists($fun_types{search})) {
		for ($i=0; $i < $fun_types{search}; $i++) {
			
			$tmp_str  = '(' . $attr_list[rand(@attr_list)];
			$tmp_str .= '=' . $chars[rand(@chars)] . '*)'; 
			push(@search_args, $tmp_str);
		}
	}


	##################
	# Combine it all #
	##################

	my (@all_ops, @all_args); # the BIG one.
	my $op;
	my $new_add = 0; # boolean 0/1
	my @op_list = keys(%fun_types);
	
	for($i = 0; $i < $settings{opcount}; $i++) {
		$op = $op_list[rand(@op_list)];

		if ($op eq 'del') {
			unless ($new_add) {
				$i--;
				next;
			}
			$new_add = 0;
			
			push(@all_ops, \&Deleter);
			push(@all_args, pop(@del_args));
			
			# stop when we've added them all
			@op_list = map { $_ eq 'del' ? () : $_} @op_list unless (scalar(@del_args));

		} elsif ($op eq 'add') {
			$new_add = 1;
			push(@all_ops, \&Adder);
			push(@all_args, pop(@add_args));

			@op_list = map { $_ eq 'add' ? () : $_} @op_list unless (scalar(@add_args));

		} elsif ($op eq 'search') {
			push(@all_ops, \&Searcher);
			push(@all_args, pop(@search_args));
			# NOTE: This has potential for the same integration metioned in the bind note below.

			@op_list = map { $_ eq 'search' ? () : $_} @op_list unless (scalar(@search_args));

		} elsif ($op eq 'bind') {
			#NOTE: This logic can probibly encase the bind populator above...
			#      However, I want to keep the current model in the case above 
			#      code gets more complex. e.g. Binding different accounts.
			push(@all_ops, \&Binder);
			push(@all_args, pop(@bind_args));

			@op_list = map { $_ eq 'bind' ? () : $_} @op_list unless (scalar(@bind_args));
		}
	

	}

	return \@all_ops, \@all_args;
}







#TODO: Bring the count back down to 100...
#TODO: make sure dels !> adds
