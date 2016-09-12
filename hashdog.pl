#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use File::Copy;
use File::Find;
use File::Spec::Functions;
use File::Path qw(make_path remove_tree);
use Digest::MD5::File qw(file_md5_hex);
use Digest::SHA;
use String::CRC32;
use Pod::Usage;

=pod

=begin changelog

# [*] changelog
# version 0.72
# added code for handling archives of multiple archive types
# added function for translating control characters to its hexadecimal value
# cleaned up some of the code

=end changelog

=cut

my $version='0.72';
my ($volume,$directories,$basename) = File::Spec->splitpath($0);
print "[*] $basename version: $version written by Par Osterberg Medina\n";

=pod

=head1 NAME

hashdog - manage hash databases

=head1 SYNOPSIS

hashdog [options] [file ...]

 Options:
   --help              brief help message
   --man               full documentation
   --input             file or directory to process

  Supported hash formats: md5, sha1sum, rds
   --[hash]-file       generate a file with [hash] checksums
   --[hash]-fullpath   use full file paths in the file with [hash] checksums

For more options, see --help or --man.

=head1 OPTIONS

=over 8

=item B<--input>

Input file or directory to process.

=item B<--md5sum-file>, B<--sha1sum-file>, B<--rds-file>

Generate a file with the selected hash/checksum format

=item B<--md5sum-fullpath>, B<--sha1sum-fullpath>, B<--rds-fullpath>

Use full file paths in the output hash file

=item B<--archive-bin>

Path to the 7zip archive executable

=item B<--archive-skip>

A comma separated list of archive types not to uncompress

=item B<--min-filesize>

The minimum size of a file (in bytes) to process

=item B<--tmp>

Specify the path to a temporary working directory

=item B<--verbose>

Enable verbose output

=item B<--debug>

Enable debuging output

=item B<-help>

Print a brief help message and exits.

=item B<-man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<hashdog> will manage hash databases in a variety of hash and output formats.

=head1 AUTHOR

Par Osterberg Medina <https://github.com/parosterbergmedina/hashdog>

Richard Harman <https://github.com/warewolf/hashdog>

=cut

# options and their default values
my ($input,@archive_skip,$verbose,$debug,$help,$man);
my ($md5sum_file,$md5sum_fullpath,$sha1sum_file,$sha1sum_fullpath,$rds_file,$rds_fullpath);
my $tmp_folder=File::Spec->tmpdir();
my $archive_bin="7z";
my $min_filesize=1;

GetOptions(
		"input|i=s"=>\$input,
		"md5sum-file=s"=>\$md5sum_file,
		"md5sum-fullpath"=>\$md5sum_fullpath,
		"sha1sum-file=s"=>\$sha1sum_file,
		"sha1sum-fullpath"=>\$sha1sum_fullpath,
		"rds-file=s"=>\$rds_file,
		"rds-fullpath"=>\$rds_fullpath,
		"archive-bin=s"=>\$archive_bin,
		"archive-skip=s"=>\@archive_skip,
		"min-filesize"=>\$min_filesize,
		"tmp=s"=>\$tmp_folder,
		"verbose|v"=>\$verbose,
		"debug|d"=>\$debug,
		"help"=>\$help,
		"man"=>\$man,
	) or pod2usage(2);

pod2usage(1)  if ($help);
pod2usage(-verbose => 2)  if ($man);


# check if we have all the options
pod2usage(-msg  => "Fatal: specify a file or directory to process with --input", -exitval => 1, -verbose => 0) unless ($input);

printf "[-] minimum filesize to process: %d byte%s\n",$min_filesize,$min_filesize>1?"s":"";

# get the version of 7-Zip
my ($archive_version);
my @output=`$archive_bin`;
&d_print(@output);

foreach my $line (@output){
	chomp($line);
	if ($line=~m/^7-Zip\s.*/){
		$archive_version=$line;
		last;
	}
}

if ($archive_version){print "[-] archive binary: $archive_version\n";}
else {die "could not find version information for 7-Zip";}

# temporary directory
my $random=int(rand(1000000)) + 100000;
$tmp_folder=File::Spec->catfile("$tmp_folder","hd$random");
print "[-] using tmp folder: $tmp_folder\n";

# archive types to skip, PE, ELF
@archive_skip=split(/,/,join(',',@archive_skip));

# creating the files handles
my ($md5sum_fh,$sha1sum_fh,$rds_fh,$sdhash_fh,$ssdeep_fh);
if ($md5sum_file){open ($md5sum_fh, '>', "$md5sum_file") or die $!;}
if ($sha1sum_file){open ($sha1sum_fh, '>', "$sha1sum_file") or die $!;}
if ($rds_file){
	open ($rds_fh, '>', "$rds_file") or die $!;
	print $rds_fh '"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"' . "\n";
}

# start processing a file or following a directory recursivly
pod2usage(-msg  => "Fatal: --input is neither a file nor a directory", -exitval => 1, -verbose => 0) unless (-d $input or -f $input);

if (-d "$input") {
	my $filetype="main_multi";
	print "[+] processing files recursivly from: $input\n";
	&recursive("$input",$filetype);
}
elsif (-f "$input") {
	my $filetype="main_single";
	print "[+] processing file: $input\n";
	&process_file("$input",$filetype);
}

my $sec=time - $^T;        
print "[+] done, finished in: " . int($sec/(24*60*60)) . " hours, " . ($sec/60)%60 . " minutes and " . $sec%60 . " seconds\n";

# close the file handles
if ($md5sum_file){close $md5sum_fh;}
if ($sha1sum_file){close $sha1sum_fh;}
if ($rds_file){close $rds_fh;}

# cleaning up the temporary directory
print "[-] deleting the tmp directory\n";
remove_tree($tmp_folder,{keep_root=>0});

exit;

sub recursive {
        my ($dir,$filetype)=@_;

        # cleaning up the temporary directory
        if ($filetype=~m/^main/){remove_tree($tmp_folder,{keep_root=>1});}

        opendir(DIR,$dir) or die "Couldn't opendir $dir for reading! ($!)";
                foreach my $file (readdir DIR){

                        # we do not want to process files named '.' or '..'
                        next if ($file=~m/^(\.|\.\.)$/);

                        # get the full path to the file
                        $file=File::Spec->catfile("$dir","$file");

                        # we do not want to process symbolic links
                        next if (-l "$file");

                        # list the directory or process the file
                        if (-d "$file") {&recursive("$file",$filetype);}
                        elsif (-f "$file") {&process_file("$file",$filetype);}
                        else {print "error: $file\n";}
                }
                closedir DIR;
        return ();
}


sub process_file {
	my ($file_to_process,$filetype)=@_;
	my $filename_fullpath=&remove_ctrl("$file_to_process");

	# getting the name of the file we are processing
	my ($volume,$directories,$file,$filename_shortpath);
	if ($filetype eq "main_single"){
		($volume,$directories,$filename_fullpath)=File::Spec->splitpath($file_to_process);
	}
	elsif ($filetype eq "main_multi"){
		$filename_fullpath=~s/^\Q$input\E(.*)/$1/i;
	}
	elsif ($filetype eq "extracted"){
		($volume,$directories,$file)=File::Spec->splitpath($tmp_folder);
		my $substitute=catfile("$directories","$file");
		chomp ($substitute);
		$filename_fullpath=~s/^\Q$substitute\E(.*)/$1/;
	}
	else {die "could not extract file name to use in hashset: $filename_fullpath\n";}
	($volume,$directories,$filename_shortpath)=File::Spec->splitpath($filename_fullpath);

	# formating the name of the file
	$filename_fullpath=~s/^[\/|\\]//; # remove the first (back)slash
	print "[+] $filename_fullpath\n";
	&v_print ("[-] path: \"$file_to_process\"\n");
	&v_print ("[-] name: $filename_shortpath\n");

	# getting the file size
	my $filesize= -s $file_to_process;
	&v_print ("[-] type: $filetype\n");
	&v_print ("[-] size:$filesize\n");

	# generate checksums files above the mimimum allowed file size
	if ($filesize >= $min_filesize){

		my ($md5sum,$sha1sum,$crc32sum);

		if ($md5sum_file){
			my $filename_in_hashset=$filename_shortpath;
			if ($md5sum_fullpath){$filename_in_hashset=$filename_fullpath;}
			if (!$md5sum){$md5sum=&get_digest($file_to_process,'md5');}
			print $md5sum_fh "$md5sum  $filename_in_hashset\n";
		}

		if ($sha1sum_file){
			my $filename_in_hashset=$filename_shortpath;
			if ($sha1sum_fullpath){$filename_in_hashset=$filename_fullpath;}
			if (!$sha1sum){$sha1sum=&get_digest($file_to_process,'sha1');}
			print $sha1sum_fh "$sha1sum  $filename_in_hashset\n";
		}

		# create a RDS compatible hashset
		if ($rds_file){
			my $filename_in_hashset=$filename_shortpath;
			if ($rds_fullpath){$filename_in_hashset=$filename_fullpath;}
			if (!$md5sum){$md5sum=&get_digest($file_to_process,'md5');}
			if (!$sha1sum){$sha1sum=&get_digest($file_to_process,'sha1');}
			if (!$crc32sum){$crc32sum=&get_digest($file_to_process,'crc32');}
			print $rds_fh "\"$sha1sum\",\"$md5sum\",\"$crc32sum\",\"$filename_in_hashset\",$filesize,0,\"WIN\",\"\"\n";
		}
	}
	else {&v_print ("[-] file \($filesize bytes\) is less than $min_filesize bytes\n");}

	# checking to see if the file is an archive
	&d_print ("[-] 7-Zip cmd: $archive_bin l \"$file_to_process\"");
	my @output=`$archive_bin l \"$file_to_process\"`;
	&d_print(@output);
	my ($archive_type);
        foreach my $line (@output){
     		chomp($line);
		# the file is an archive if we find an archive type
		if ($line=~m/^Type\s=\s(.*)/){ 
			$archive_type.=$1;
		}
	}

	# process the file as an archive
	if ($archive_type){

			# PE files, try to unpack using the file
			if ($archive_type=~m/^PE$/){
				# add check for files packed with UPXs
			}

			foreach my $skip (@archive_skip){
				if ($archive_type=~m/^$skip$/i){
					&v_print("[-] skipping archive type: $archive_type\n");
					return ();
				}
			}

			if ($filetype eq "extracted"){
				my $tmp_folder_location=File::Spec->catfile("$tmp_folder","tmp_folder_file.tmp");
				&v_print("[-] moving $file_to_process to $tmp_folder_location\n");
				move ($file_to_process,$tmp_folder_location) or die "could not move file: $!";
				$file_to_process=$tmp_folder_location;
			}

			# making directory that will hold the content of the archive
			my $archive_output=catfile("$tmp_folder","$filename_fullpath");
			my ($volume,$directories,$file) = File::Spec->splitpath($archive_output);
			$archive_output=catfile("$directories","$file");
			# if we have a volume, use the "\\?\" prefix to specify extended-length path
			if ($volume){make_path ("\\\\\?\\$volume$archive_output");}
			else {make_path ("$archive_output");}

			# extracting the archive
			print "[-] extracting archive: $archive_type\n";
			my $cmd="$archive_bin x \"$file_to_process\" -o\"$archive_output\" -aou -p1";
			&v_print("[-] executing command: $cmd\n");
			my @extract_output=`$cmd`;
			my $archive_bin_exit=$? >> 8;
			&d_print(@extract_output);

			# making sure we can read the extracted files
			find ( sub { chmod 0755, $_ or warn "cannot chmod $File::Find::name: $!"; }, $archive_output);
			
			# deleting the temporary file		
			if ($filetype eq "extracted"){unlink "$file_to_process" or die "could not delete: $file_to_process: $!";} 
		
			if ($archive_bin_exit != 0){
				print "[-] archive is corrupt or password protected (exit code: $archive_bin_exit)\n";
				&v_print("[-] deleting archive");
				remove_tree($archive_output,{keep_root=>0});
				return ();
			}

			# processing the extracted archive
			&recursive($archive_output,"extracted");
			return ();
	}
	&v_print("[-] archive: not an archive\n");
	return ();
}


sub v_print {
	my (@input)=@_;
	if ($verbose){foreach my $line (@input){print "$line";}}
	return ();
}

sub d_print {
	my (@input)=@_;
	if ($debug){
		foreach my $line (@input){
			chomp ($line);
			print "$line\n";}
	}
	return ();
}

sub get_digest {
        my ($file,$type)=@_;
	my ($digest,$file_fh);
	if ($type eq 'md5'){$digest=file_md5_hex($file);}
	elsif ($type eq 'sha1'){$digest=Digest::SHA->new(1)->addfile("$file")->hexdigest;}
	elsif ($type eq 'crc32'){
		open ($file_fh,"<", $file) || die "Couldn't open $file: $!";
		$digest=sprintf("%08x",crc32(*$file_fh)); # change to capital X for UC
		close($file_fh);
	}
	&v_print("[-] $type: $digest\n");
	if (!$digest){die "failed to produce $type digest for $file: $!";}
        return ($digest);
}

sub remove_ctrl {
        my ($string)=@_;
        my ($safe);
        my @chars=split(//,$string);
        foreach my $char (@chars){
                if ($char=~m/[\x00-\x1F]/){
                        my $hex=unpack('C*', $char);
                        $char=sprintf("\\x%02x",$hex);
                }
                $safe.="$char";
        }
return ($safe);
}

