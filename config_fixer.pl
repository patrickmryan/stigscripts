#!/usr/bin/perl

use File::Basename;


sub fix_config_file   # filename, regexp, replacement text
{
    #
    #
    #
    #
    #
    #

    
    my $filename = shift;
    my $regexp = shift;
    my $newtext = shift;
    
    # make sure newtext includes a terminal newline
    if ($newtext !~ /\n$/) {
	$newtext = "$newtext\n";
    }

    if ( ! -f "$filename" ) {
	print "$filename : not found\n";
	return;
    }

    @newcontent = ();
    open CFG, "<$filename";
    @content = <CFG>;
    close CFG;

    $found = 0;
    foreach $line (@content) {
	
	if (($line =~ /$regexp/) && # found the line
	    ($line !~ /^\s*#/ )) { # make sure it's not already a comment

	    @newcontent = (@newcontent,  "### $line");  # save the original line as a comment
	    @newcontent = (@newcontent, $newtext); # append the new line
	    $found = 1;
	    
	} else {
	    @newcontent = (@newcontent, $line);
	}

    }

    if (!$found) { # nothing to do
	print "$filename: no change\n";
	return;
    }
    
    backup($filename);
  
    $newfile = "$filename.$$";
    
    open(NEWFILE, ">$newfile") || die $!;
    foreach (@newcontent) {
	print NEWFILE $_;
    }
    close NEWFILE;
    copy_permissions($filename, $newfile);

    $oldfile = "$filename.old";
    rename $filename, $oldfile; # rename the existing file 
    rename $newfile, $filename; # move the new one in it's place
    unlink $oldfile;            # whack the old file
    
}

sub copy_permissions
{
    my ($source, $target) = @_;
    
    ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
     $atime,$mtime,$ctime,$blksize,$blocks)
	= stat($source);

    chmod $mode, $target;
    chown $uid, $gid, $target;    
}




#sub basename
#{
#    my $path = shift;
#    if ($path =~ m|/|) { # does the path include a slash?
	# if so, extract everything after the slash
#	($base) = ($path =~ m|.*/([^/]+)$|)
#    } else {
	# if not, just return the input
#	$base = $path;
#    }
#    $base;
#}

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
	#$basefile = basename $file;
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


# main program starts here

###die "count = $#ARGV";

if ($#ARGV != 2) {
    die "need three arguments\n";
}


$configfile = $ARGV[0];
$regexp = $ARGV[1];
$newtext = $ARGV[2];

#backup $configfile; exit 0;

print "file = $configfile,re = $regexp, new = $newtext\n";

fix_config_file($configfile,$regexp,$newtext);
