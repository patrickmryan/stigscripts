#!/usr/bin/perl
#
# Patrick M. Ryan, IBM Federal Software, pmryan@us.ibm.com
#
# This script resolves about 30 findings identified by the SCAP Compliance Checker (SCC).
# This will not resolve every deviation!  The purpose of the script is to speed remediation
# and ensure that the exact same steps are taken on every server.
#
# This script has not been tested extensively so take care when using.  The best approach is 
# to use this on virtual servers and to snapshot before running the script.
#
# The script will print the STIG rule before taking the actions. 
#
# There is a debug mode for this script.  When in that mode, the script will display the
# commands it would take but will not execute them.
#
# The script will also backup any file which will be replaced by the script.  The script
# will append a number to the backup file.  The idea is that the original file will never
# get lost, no matter how many times you run the script.
#
# Finally, it's best to run this in the context of a Unix "script" command so as to capture
# all of the standard output.
#
#
#
#

use File::Basename;

sub debug
{
    # To put this script in DEBUG mode, return any value other than zero.
    return 0;
}

sub execute
{
    # Use this method to invoke a system command.  If the script is in DEBUG mode, the
    # routine will print the command but not actually run it.
    
    my $cmd = join ' ',@_;
    if (!debug()) {
	print "$cmd\n";
	system $cmd;
    } else {
	print "DEBUG: $cmd\n";
    }
}

sub backup
{
    # This routine makes a backup copy of the list of files.  The
    # argument to this routine is one or more files to be backed up.
    
    my $backupdir = "./backup";
    if ( ! -d $backupdir ) {
	system "mkdir $backupdir" ||
	    die "could not create backup directory $backupdir\n";
    }
    
    
    for my $file (@_) {
	my($basefile,$dirs) = fileparse($file);

	if ( -f $file ) {
	    $backupfile = next_backup_filename($backupdir,$basefile);

	    $cmd = "/bin/cp $file $backupdir/$backupfile";	    
	    printf "$cmd\n";
	    system $cmd;
	} else {
	    print "no file $file to back up\n";
	}
    }
}

sub next_backup_filename
{
    # Determine the next backup file name.  Routine accepts two arguments, the backup
    # directory and the file to be backed up.
    # If this is the first time the file will be backed up, the backup file name will be the
    # original name appended with ".01".  Subsequent backups will increment the suffix.
    
    my $backupdir = shift;
    my $original = shift;
    $ver = 1;
    while (true) {
	my $backup = sprintf "$original.%02d", $ver;
	my $nextfile = "$backupdir/$backup";
	#### printf "testing next file $nextfile\n";
	if ( ! -f $nextfile ) { return $backup; }
	++$ver;
    }
}

sub copy {
    my $sourcefile = shift;
    my $targetdir  = shift;
    execute("/bin/cp $sourcefile $targetdir");
}

sub collect_partitions {
    my @mounts = ();
    open(MTAB,"</etc/mtab");
    while (<MTAB>) {
	chop;
	($dev,$dir,$type) = split /\s+/;
	@mounts = (@mounts,$dir);
    }
    close MTAB;
    @mounts;
}

sub fix_sticky_bits {
    my $dir = shift;
    my $findcmd = "find $dir -xdev -type d -perm -002 '!' -perm -1000";
    print "$findcmd\n";
    @suspects = `$findcmd`;
    foreach $suspect (@suspects) {
	chop $suspect;
	$cmd = "chmod +t $suspect";
	execute $cmd;
    }
}

sub find_world_writable_dirs {
    my $dir = shift;
    my $findcmd = "find $dir -xdev -type d -perm -0002 -uid +499 -print";
    printf "$cmd\n";
    @suspects = `$findcmd`;
    foreach $suspect (@suspects) {
	chop $suspect;
	print "INVESTIGATE $suspect\n";
    }
}

sub find_misowned_files {
    my $rpmfile = shift;
    my @misowned = ();
    # this regexp combines the queries from 
    # RHEL-06-000516 and RHEL-06-000517
    my $cmd = "grep '^.....U|^......G' < $rpmfile";
    print "$cmd\n";
    @output = `$cmd`;
    foreach (@output) {
	chop;
	($audit,$file) = split /\s+/;
	print "misowned -> $file\n";
	@misowned = (@misowned,$file);
    }
    return @misowned;
}

sub fix_ownership {
    my @wayward = @_;
    my @packages = ();
    ###my $object = "";
    foreach $object (@wayward) {
	# ignore messages about read locks, send stderr to /dev/null 
	$cmd = "rpm -qf $object 2> /dev/null";
	print "$cmd\n";
	@packages = `$cmd`;
	foreach $pkg (@packages) {
	    # iterate over packages that use this file
	    chop $pkg;
	    $cmd = "rpm --setugids $pkg";
	    execute($cmd);
	}
    }
}

sub get_rpmVa
{
    # The system command "rpm -Va" takes 20-30 minutes to run. We'd prefer to only run
    # it once.  If you need to refresh the data, delete /tmp/rpmVa.txt.
    
    my $tmpfile = "/tmp/rpmVa.txt";
    if ( -f $tmpfile ) { # id the file already exists, use it
	return $tmpfile;
    }

    my $cmd = "rpm -Va > $tmpfile 2> /dev/null";
    execute($cmd);
    $tmpfile;
}

sub find_changed_files
{
    my $rpmfile = shift;
    my @changed = ();
    my $cmd = "awk \'\$1 ~ /..5/ && \$2 != \"c\"\' < $rpmfile";

    print "$cmd\n";
    @output = `$cmd`;
    foreach (@output) {
	chop;
	($audit,$file) = split /\s+/;
	@changed = (@changed,$file);
    }
    @changed;
}

###########

# End of subroutines

###########

# Actual script starts here

###########

print "RHEL-06-000015\n";

$script=<<_SHELL_;
cd /etc/yum.repos.d
for f in *.repo ; do
	if [ `grep gpgcheck=0 \$f` ] ; then
		echo removing gpgcheck=0 from \$f
		grep -v gpgcheck=0 \$f > \$f.tmp
		/bin/mv \$f.tmp \$f
	fi
done

_SHELL_

system $script;

print "RHEL-06-000061, RHEL-06-000356, RHEL-06-000357\n";

for my $f ('system-auth', 'password-auth')
{
    backup("/etc/pam.d/$f");
    copy("reference/$f","/etc/pam.d/");
}

print "RHEL-06-000098\n";

$dir='/etc/modprobe.d';
$name='disabled.conf';
$file="$dir/$name";
backup($file);
copy("reference/$name","$dir");

##`print "RHEL-06-000113 and RHEL-06-000117\n";
##`execute("service iptables start");

print "RHEL-06-000124\n";
copy("reference/nodccp.conf","/etc/modprobe.d/");

print "RHEL-06-000125\n";
copy("reference/nosctp.conf","/etc/modprobe.d/");

print "RHEL-06-000127\n";
copy("reference/notipc.conf","/etc/modprobe.d/");

print "RHEL-06-000136\n";
backup("/etc/rsyslogd.conf");
copy("reference/rsyslogd.conf","/etc/");

##`print "RHEL-06-000320\n";
##`backup("/temp/iptables");
##`execute("iptables-save > /tmp/iptables");
##`backup("/tmp/iptables");
##`execute("iptables-restore < reference/iptables");
##`execute("iptables-save > /etc/sysconfig/iptables");

print "RHEL-06-000331\n";
execute("chkconfig bluetooth off");
execute("service bluetooth stop");

print "RHEL-06-000503\n";
copy("reference/nousb.conf","/etc/modprobe.d/");

print "RHEL-06-000510, RHEL-06-000511\n";
backup("/etc/audit/auditd.conf");
copy("reference/auditd.conf","/etc/audit/");

print "RHEL-06-000009\n";
execute("service rhnsd stop");
execute("chkconfig rhnsd off");

print "RHEL-06-000015\n";
backup("/etc/yum.repos.d/packagekit-media.rep");
copy("reference/packagekit-media.rep","/etc/yum.repos.d/");

print "RHEL-06-000083, 84, 86, 88,   \n";
backup("/etc/sysctl.conf");
execute("sysctl -w net.ipv4.conf.all.accept_source_route=0");  # 000083
execute("sysctl -w net.ipv4.conf.all.accept_redirects=0");     # 000084
execute("sysctl -w net.ipv4.conf.all.secure_redirects=0");     # 000086
execute("sysctl -w net.ipv4.conf.all.log_martians=1");         # 000088
copy("reference/sysctl.conf","/etc");

print "RHEL-06-000126\n";
copy("reference/nords.conf","/etc/modprobe.d/");

print "RHEL-06-000167, RHEL-06-000188, RHEL-06-000197, RHEL-06-000201 \n";
backup("/etc/audit/audit.rules");
copy("reference/audit.rules","/etc/audit/");

print "RHEL-06-000261\n";
execute("chkconfig abrtd off");
execute("service abrtd stop");
 
print "RHEL-06-000262\n";
execute("chkconfig atd off");
execute("service atd stop");

print "RHEL-06-000335\n";
backup("/etc/default/useradd");
copy("reference/useradd","/etc/default/");

print "RHEL-06-000336\n";
@partitions = collect_partitions();
foreach $dir (@partitions) {
    print "fixing $dir\n";
    fix_sticky_bits($dir);
}

print "RHEL-06-000337\n";
foreach $dir (@partitions) {
    print "finding world-writable directories under $dir\n";
    find_world_writable_dirs($dir);
}

print "RHEL-06-000342\n";
backup("/etc/bashrc");
copy("reference/bashrc","/etc/");

print "RHEL-06-000343\n";
backup("/etc/csh.cshrc");
copy("reference/csh.cshrc","/etc/");

print "RHEL-06-000344\n";
backup("/etc/profile");
copy("reference/profile","/etc/");

print "RHEL-06-000509\n";
backup("/etc/audisp/plugins.d/syslog.conf");
copy("reference/syslog.conf","/etc/audisp/");

# The next few rules use output from rpm -Va. This command
# takes a long time so we'll save the output in a temp file.

print "stand by, this takes a while...\n";
$rpmfile = get_rpmVa();
##$rpmfile = "/tmp/rpmdata.txt";

print "RHEL-06-000516, RHEL-06-000517\n";
@deviants = find_misowned_files($rpmfile);
foreach $d (@deviants) { printf "($d) "; }
printf "\n";
fix_ownership(@deviants);

print "RHEL-06-000519\n";
@changed = find_changed_files($rpmfile);
# Can't fix these automatically.  Print them for investigation
foreach (@changed) {
    print "has mismatch on $_\n";
}

