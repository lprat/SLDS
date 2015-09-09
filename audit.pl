#!/usr/bin/perl
#/usr/local/bin/audit.pl
sub hex2dec($) { return hex $_[0] }
my $savid="";
my $savline="";
while ($line = <STDIN>){
    chomp;
    ($null,$newid)=split(/ /,$line);
    if($savid eq $newid){
      #id identique
      if($line =~ /^type=SOCKADDR msg=audit\(\S+\): saddr=(\S+)/){
	my $saddr=$1;
	($f1, $f2, $p1, $p2, @addr) = unpack("A2A2A2A2A2A2A2A2", $saddr);
	$family = hex2dec($f1) + 256 * hex2dec($f2);
	if ($family eq 2) {
	  $port = 256 * hex2dec($p1) + hex2dec($p2);
	  $ip1 = hex2dec($addr[0]);
	  $ip2 = hex2dec($addr[1]);
	  $ip3 = hex2dec($addr[2]);
	  $ip4 = hex2dec($addr[3]);
	  $savline=$savline." SOCKADDR saddr=$saddr saddr_ip=$ip1.$ip2.$ip3.$ip4 saddr_port=$port saddr_family=AF_INET";
	} elsif($family eq 10) {
	  $savline=$savline." SOCKADDR saddr=$saddr saddr_family=AF_INET6";
	} elsif($family eq 1) {
	  $savline=$savline." SOCKADDR saddr=$saddr saddr_family=AF_UNIX";
	} else {
	  $savline=$savline." SOCKADDR saddr=$saddr saddr_family=$family";
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* Appletalk DDP 		*/
#define	AF_NETROM	6	/* Amateur radio NetROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_AAL5		8	/* Reserved for Werner's ATM 	*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_MAX		12	/* For now.. */
	}
      }else{
	$line =~ s/[\n]+//g;
	$savline=$savline." ".$line;
      }
    } else {
      #id diff, print cache, savline courant
      $savid=$newid;
      $line =~ s/[\n]+//g;
      print $savline."\n";
      $savline=$line;
    }
}
##########################
