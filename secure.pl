#!/usr/bin/perl
#Script de sécurisation des serveurs linux Debian & CentOS
#ver svn 98
use Switch;
use Expect;
#apt-get install -y libexpect-perl
use IO::File;
#variables
my $DEBUG=0; # debug script 0=no ; 1=yes
my $osissue = '/etc/issue';
my $typeos=0; # 1 = debian | 2 = centos
my $typedeb=0; # 1 = debian squeeze | 2 = wheezy
my $pkg_ori; # packages installés sur l'os lors de l'installation d'origine
my $pkg_nodep; # packages installés sur l'os après installation d'origine sans dépendance
my $pkg_dep; # packages installés sur l'os après installation d'origine avec dépendance
my $pkg_md5; # sig md5 packages
my $services_on; #services installés & lancés sur l'os
my $services_off; #services installés & non lancés sur l'os
my $ras; # variable pour execution standard
my $login; #verify root uid
my $listproc; #list processus par lsof -l
# plus la note est élévé pour un process, moins le risque est grand
my $note_proc=0; # note secure proc 0 à 5
my $note_lib=0; # note secure lib dynamiques attachées au proc: 0 à 5 doit etre minimum >= 1
my $note_net=0; # note si proc communication NETIPV4/IPV6 2 == no net | -2 == net 
my $note_pkg=0; # note si proc fait partie d'un packages 1 == pkg | 0 == no pkg alors note_proc >= 4
my $note_init=0; # note si proc fait partie de init 0 == init || 1 == no init
#variable test note fixe
my $min_risk=5; # note indiquant un risque si non atteint
my $choix_net=0; # note indiquant un risque si non atteint
my $clear_string = `clear`; #clear screen
my $interfaceserv=0; #interface service ethX
my $myipserv=0; #adresse ip service sur interface service
my $interfacepriv=0; #interface admin priv ethX
my $myippriv=0; #adresse ip privé sur interface admin
my $myippub=0; #adresse ip sur interface public
my $kernelver=0; # version kernel
my $servadd=0; #service a installer
my $tomoyo=0; #tomoyo 0 disable, 1 enable
my $apparmor=0; #apparmor 0 disable, 1 enable
my @dnsserv; # serveur DNS dans /etc/resolv.conf
my $tomoyoact=0; # tomoyo activation 0 disable ; 1 enable
my $cgroupsactk=0; # cgroups Kernel version possible 0 disable ; 1 enable
my $cgroupsact=0; # cgroups activation 0 disable ; 1 enable
my $tomoyoacten=0; # tomoyo activation enable kernel 0 disable ; 1 enable
my $cgroupsacten=0; # cgroups activation enable kernel 0 disable ; 1 enable
my $DEB_PUB=""; # debit sur interface public
my $DEB_PRIV=""; # debit sur interface prive
my $NTPSERV=""; # ntp serveur
my $NRPESERV=""; # nagios serveur requet nrpe
my $SYSLOGSERV=""; # syslog central serveur
my $PUBCLASS=0; # nombre de classe QOS public 
my $PRIVCLASS=0; # nombre de classe QOS priv
my $ossecserv=""; #ossec ip serveur
##########################################
#implem bash to perl test syntaxe
##!/usr/bin/perl
#use IO::File;
#$fh = new IO::File;
#$fh->open("translate.sh","w");
#    print $fh <<EOF;
##!/bin/sh
#$info_tmp=`dpkg -s $pkg_tmp|sed -e ':z;N;s/\\n\\s/||/;bz'|grep -iE "^package:|^Section:|^Description:"|sed -e 's/||/\\n /g'`;
#lsof -l | grep -i "txt" | awk '{print \$1" "$NF}' | sort -u |grep -i " /"|grep -iv " /proc/" > /tmp/lsof-list;awk '{print \$2}' /tmp/lsof-list | awk -F "/" '{print "dpkg -S "\$NF" 2>/dev/null|grep -i \\\""\$0"$\\\""}'  | sh |sort -u > /tmp/lsof-list2; awk '{print "echo "\$1" `grep -i \\\""\$2"\\\" /tmp/lsof-list`" }' /tmp/lsof-list2  |sh | awk '{print "Package: "\$1"== process "\$2}'|sed 's/://g'|sort -u >/tmp/lsof-listx;awk '{print "echo Process "\$1": `if(!(grep -i \\\""\$2"$\\\" /tmp/lsof-list2));then echo \\\"ne fait pas partie de package\\\";fi`" }' /tmp/lsof-list |sh| grep -i "ne fait pas partie" >> /tmp/lsof-listx
#EOF
##########################################
#presentation
print "Script Secure Linux Debian & CentOS v0.1 by lionel.prat9\@gmail.com\n";
print "Le script permet de renforcer la securité des distributions Debian (squeeze & wheezy - non testé sur lenny) ainsi que Centos 5 et 6.\n";
print "Cependant, il est grandement recommandé d'utiliser Debian qui me semble plus adapté au niveau securité car la majorité des outils sont disponibles dans les depots de base.\n";
print "De plus, debian vous permettra d'upgrade votre version facilement (ex: lenny->squeeze) alors que centos ne le permet pas!\n";
print "\n	ATTENTION veuillez installer tous les services principales (role du serveur) avant l'utilisation du script.\n	Les services d'administration seront installés par le script: ntp, ssh, nrpe, syslog, smtp local.\n";
print "Appuyer sur une touche pour continuer.\n";
$input = <STDIN>;
##########################################
#verifie execution en root
$login = (getpwuid $>);
die "must run as root" if $login ne 'root';
##########################################
#definir si os "debian" ou "centos"
if (-e $osissue) {
  open (FIC,$osissue) || die ("Le fichier $osissue n'existe pas\n");
  while (<FIC>)
  {
    if ($_ =~ /Debian/i){
      $typeos=1;
      print "Distribution DEBIAN Linux: $_\n";
      if ($_ =~ /7/i){
	$typedeb=2;
      }
      if ($_ =~ /6/i){
	$typedeb=1;
      }
    }
    if ($_ =~ /CentOS/i){
      $typeos=2;
      print "Distribution CENTOS Linux: $_\n";
    }
  }
  close(FIC);
  if( $typeos == 0 || $typeos > 2 ){
    print "La distribution linux n'a pas été reconnu compatible avec le script...\n";
    exit;
  }
} else {
  print "La distribution linux n'a pas été reconnu compatible avec le script...\n";
  exit;
}
print "Appuyer sur une touche pour continuer.\n";
$input = <STDIN>;
##########################################
#check kernel version pour cgroups
$kernelver=`uname -r`;
if($kernelver =~ /^3./i || $kernelver =~ /^2.(7|8|9)/ || $kernelver =~ /^2.6.(3|4|5|6|7|8|9)/ || $kernelver =~ /^2.6.2(4|5|6|7|8|9)/){
  $cgroupsactk=1;
}
##########################################
#interface d administration 
print $clear_string; 
print "Disposez vous d'une interface réseau spécifique à l'administration en classe privé? (Oui/Non)\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Veuillez indiquer le nom de l'interface: ";
  $interfacepriv = <STDIN>;
  $interfacepriv =~ s/\n//g;
  my $cmd=`if(ifconfig $interfacepriv);then echo TESTok;else echo ko;fi`;
  if ($cmd =~ /TESTok/){
    $myippriv=`ifconfig $interfacepriv | grep -i "inet adr"|awk '{print \$2}'|cut -d ":" -f 2`;
    $myippriv =~ s/\n//g;
    if($myippriv =~ /^192.168./ | $myippriv =~ /^10./ | $myippriv =~ /^172.(1|2)[0-9]./ | $myippriv =~ /^172.3(0|1)./){
      print "Votre ip privée est $myippriv sur l'interface $interfacepriv\n";
    } else {
      print "L'IP obtenu sur l'interface $interfacepriv n'est pas une adresse IP privée: $myippriv .\nVeuillez créer une interface de ce type pour pouvoir executer le script et obtenir un niveau de securité convenable...\n";
    exit 0;
    }
  } else {
    print "L'interface $interfacepriv n'existe pas.\nVeuillez créer une interface de ce type pour pouvoir executer le script et obtenir un niveau de securité convenable...\n";
    exit 0;
  }
} else {
  print "Veuillez créer une interface de ce type pour pouvoir executer le script et obtenir un niveau de securité convenable...\n";
  exit 0;
}
print "Appuyer sur une touche pour continuer.\n";
$input = <STDIN>;
##########################################
#CGROUP activer
print $clear_string; 
$ras=`grep -iE "(^GRUB_CMDLINE_LINUX=).*(cgroup_enable=memory swapaccount=1)" /etc/default/grub`;
if($ras =~ /cgroup_enable/i){
  print "Cgroups activé dans le kernel!\n";
  $cgroupsacten=1;
}else{
  if($cgroupsactk == 1){
    print "Mise en place de CGROUPS\n";
    switch ($typeos){
      case '1' { #debian
	$ras=`apt-get install -y cgroup-bin libcgroup1 2> /dev/null`;
	$ras=`sed -i.bak 's/\\/mnt\\//\\/sys\\/fs\\//g' /etc/cgconfig.conf`;
	# $ras=`echo "all = /sys/fs/cgroup/devices;" >> /etc/cgconfig.conf`;
	#wheezy
	if ($typedeb == 2){
	  $ras=`apt-get install -y binutils`;
	  $ras=`wget -O /tmp/cgroup.deb http://ftp.fr.debian.org/debian/pool/main/libc/libcgroup/cgroup-bin_0.36.2-3+squeeze1_amd64.deb;cd /tmp;ar vx /tmp/cgroup.deb data.tar.gz;cd /tmp;tar -xzvf /tmp/data.tar.gz`;
	  $ras=`mkdir /cgroup;echo "mount {" > /etc/cgconfig.conf;echo "        cpu = /cgroup/cpu;" >> /etc/cgconfig.conf;echo "        cpuacct = /cgroup/cpuacct;" >> /etc/cgconfig.conf;echo "        memory = /cgroup/memory;" >> /etc/cgconfig.conf;echo "        devices = /cgroup/devices;" >> /etc/cgconfig.conf;echo "}" >> /etc/cgconfig.conf`;
	  $ras=`cp /tmp/etc/default/* /etc/default/; cp /tmp/etc/init.d/* /etc/init.d/;cp /tmp/etc/cgrules.conf /etc/cgrules.conf;update-rc.d cgconfig defaults;update-rc.d cgconfig enable;update-rc.d cgred defaults;update-rc.d cgred enable`;
	}
	$cgroupsact=1;
      }
      case '2' { #centos
	#centos 6 : libcgroup
	$ras=`yum install -y  libcgroup 2> /dev/null`;
	$cgroupsact=1;
      }
    }
  }
}
print "Appuyer sur une touche pour continuer.\n";
$input = <STDIN>;
##########################################
#TOMOYO
#dans edit-policy la touche w permet de changer de mode:
#e     <<< Exception Policy Editor >>>                                                                                                                                              
#d     <<< Domain Transition Editor >>>                                                                                                                                             
#a     <<< Domain Policy Editor >>>  ref: http://tomoyo.sourceforge.jp/2.5/policy-specification/domain-policy-syntax.html.en                                                                                                                                        
#p     <<< Profile Editor >>>                                                                                                                                                       
#m     <<< Manager Policy Editor >>>                                                                                                                                                
#n     <<< Namespace Selector >>>                                                                                                                                                   
#s     <<< Statistics >>>               
#dans Exception Policy Editor : vous pouvez créer une exception qui permettra de placer des appels a d'autre applications depuis l'application dans le premier domaine. ref:http://tomoyo.sourceforge.jp/2.5/chapter-5.html.en
#profile policy (touche s dans editpolicy): 1 = apprentissage | 2 = permissif | 3 == enforcing
#tomoyo-setprofile 1 '<kernel> /usr/sbin/sshd' 
#tomoyo-setprofile -r pour selectionné tous les domaines
#choix tomoyo car plus de possibilité au niveau filtrage reseau
#http://tomoyo.sourceforge.jp/2.5/policy-specification/expression-rules.html.en
print $clear_string; 
$ras=`grep -iE "(^GRUB_CMDLINE_LINUX=).*(security=tomoyo)" /etc/default/grub`;
if($ras =~ /tomoyo/i){
  print "Tomoyo activé dans le kernel!\n";
  $tomoyoacten=1;
}else{
  print "Voulez vous installer TOMOYO sur votre serveur afin de proteger vos services sensibles (externe)?\n";
  print "Veuillez entrer soit: tomoyo ou aucun\n";
  $input = <STDIN>;
  if ($input =~ /^tomoyo/i){
    $tomoyo=1;
    print "Installation de tomoyo...";
    switch ($typeos) {
	  case '1' { #debian
	    $ras=`/usr/bin/apt-get install -y tomoyo-tools`;
	    $ras=`/usr/lib/tomoyo/init_policy`;
	    $ras=`if(grep -e "none     /sys/kernel/security securityfs defaults            0      0" /etc/fstab);then echo OK;else echo "none     /sys/kernel/security securityfs defaults            0      0" >> /etc/fstab;fi`;
	    $tomoyoact=1;
	  }
	  case '2' { #centos
	    #wget -O /etc/yum.repos.d/ccs.repo http://tomoyo.sourceforge.jp/repos-1.8/CentOS5/ccs.repo
	    #wget -O /etc/yum.repos.d/ccs.repo http://tomoyo.sourceforge.jp/repos-1.8/CentOS6/ccs.repo
	    #desactiver iptables ou creer une regle pour wget!!!!!!!!!!!
	    $ras=`wget http://I-love.SAKURA.ne.jp/kumaneko-key -O /tmp/kumaneko-key;rpm --import /tmp/kumaneko-key;wget -O /etc/yum.repos.d/ccs.repo http://tomoyo.sourceforge.jp/repos-1.8/CentOS5/ccs.repo;/usr/bin/yum install -y ccs-kernel ccs-tools`;
	    if ($DEBUG==1){ print "$ras";}
	    $ras=`/usr/lib/tomoyo/init_policy`;
	    $tomoyoact=1;
	  }
    }
    $ras=`echo "/var/log/tomoyo/*.log {" > /etc/logrotate.d/tomoyo`;
    $ras=`echo "  weekly" >> /etc/logrotate.d/tomoyo`;
    $ras=`echo "  rotate 9" >> /etc/logrotate.d/tomoyo`;
    $ras=`echo "  missingok" >> /etc/logrotate.d/tomoyo`;
    $ras=`echo "  notifempty" >> /etc/logrotate.d/tomoyo`;
    $ras=`echo "  nocreate" >> /etc/logrotate.d/tomoyo`;
    $ras=`echo "  compress" >> /etc/logrotate.d/tomoyo`;
    $ras=`echo "}" >> /etc/logrotate.d/tomoyo`;
    $ras=`if(grep -e "/usr/sbin/tomoyo-auditd" /etc/rc.local);then echo OK;else echo "/usr/sbin/tomoyo-auditd" >> /etc/rc.local;sed -i '/exit 0/d' /etc/rc.local;echo "exit 0" >> /etc/rc.local;fi`;
    print "OK\n";
  } else {
    print "Vous avez choisie de ne pas installer apparmor et tomoyo...\n";                                       
  }
}
print "Veuillez appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;  
##########################################
#GRUB UPDATE & REBOOT
if($tomoyoact==1 || $cgroupsact==1){
  open(inFILE, "</etc/default/grub") or die "Impossible d'ouvrir le fichier /etc/default/grub";
  open(outFILE, ">/etc/default/grub.new") or die "Impossible d'ouvrir le fichier /etc/default/grub.new";
  while (<inFILE>){
    if ($_ =~ /^GRUB_CMDLINE_LINUX=/i){
      print "Configuration actuel de GRUB: $_\n";
      my $grub="";
      if($cgroupsact == 1){
	$grub="GRUB_CMDLINE_LINUX=\"cgroup_enable=memory swapaccount=1 security=tomoyo\"";
      } else {
	$grub="GRUB_CMDLINE_LINUX=\"security=tomoyo\"";
      }
      print "Configuration mise en place: $grub\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec GRUB_CMDLINE_LINUX=\"\")\n";
	my $grubtmp = <STDIN>;
	$grubtmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $grubtmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $grub=$grubtmp;
	}
      }
      print outFILE $grub;
      print outFILE "\n#".$_;
    }else {
      print outFILE $_;
    }
  }
  close inFILE;
  close outFILE;
  $ras=`mv /etc/default/grub.new /etc/default/grub`;
  $ras=`update-grub`;
  print "Pour activer les modules kernels de securité que vous avez choisie, il faut rebooter...\nApres le reboot, relancer le script! Merci.\n";
  print "Veuillez appuyer sur une touche pour continuer...\n";
  my $input = <STDIN>;  
  $ras=`shutdown -r now`;
  exit 0;
}
##########################################
#MAJ des packages installés
print $clear_string; 
print "Mises à jour des packages installés...";
switch ($typeos) {
        case '1' { #debian
	  $ras=`/usr/bin/apt-get update;/usr/bin/apt-get upgrade -y;apt-get autoremove -y;apt-get clean -y`;
	  if ($DEBUG==1){ print "$ras";}
	}
        case '2' { #centos
	  $ras=`/usr/bin/yum update -y;yum clean all -y`;
	  if ($DEBUG==1){ print "$ras";}
	}
}
print "OK\n";
print "Appuyer sur une touche pour continuer.";
$input = <STDIN>;
print $clear_string; 
print "Voulez vous mettre en place la mise a jour des packages de securité automatiquement? (Oui/Non)\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
#MAJ de securité installation automatiquement
#debian: unattended-upgrades  & ref: https://help.ubuntu.com/10.04/serverguide/automatic-updates.html
#centos ref: http://syamsul.net/2011/01/02/unattended-updates-on-centos/ & http://syamsul.net/2012/06/14/unattended-updates-on-centos-6/
  switch ($typeos) {
	  case '1' { #debian
	    $ras=`/usr/bin/apt-get install -y unattended-upgrades`;
	    print "Configuration dans /etc/apt/apt.conf.d/50unattended-upgrades...\n";
	    print "Vous pouvez restreindre des packages de la mise a jour de securité (exemple: service sensible) par Unattended-Upgrade::Package-Blacklist {}\n";
	  }
	  case '2' { #centos
	    $ras=`/usr/bin/yum install -y yum-plugin-security yum-security`; #centos 5: yum-security & centos 6: yum-plugin-security
	    #add crontab cmd; yum --security update -y
	    $ras=`echo "#!/bin/sh" > /etc/cron.daily/yumsecurity`;
	    $ras=`echo "mount -o remount,rw /usr && mount -o remount,exec /var && mount -o remount,exec /tmp" > /etc/cron.daily/yumsecurity`;
	    $ras=`echo "/usr/bin/yum --security update -y" > /etc/cron.daily/yumsecurity`;
	    $ras=`echo "mount -o remount,ro /usr ; mount -o remount,noexec /var && mount -o remount,noexec /tmp" > /etc/cron.daily/yumsecurity`;
	    print "Ajout de la mise a jour de securité automatique dans /etc/cron.daily/yumsecurity\n";
	  }
  }	
}
print "Appuyer sur une touche pour continuer.";
$input = <STDIN>;
##########################################
#auditd
print $clear_string; 
print "Installation service auditd...\n";
my $archi="";
switch ($typeos) {
  case '1' { #debian
    $ras=`/usr/bin/apt-get install -y auditd`;
    #verif archi
    $archi=`dpkg --print-architecture|sed -e 's/[^0-9]//g'`;
    $archi="-F arch=b".$archi;
  }
  case '2' { #centos
    $ras=`/usr/bin/yum install -y audit`;
    #TODO add test achi
    $archi="-F arch=b64";
  }
}
$archi =~ s/\n//g;
print "Architecture type auditd: $archi.\n";
#installation
print "Mise en place des regles auditd de base...\n Vous pouvez modifier les règles dans /etc/audit/audit.rules\n";
#regle trace commande
$ras=`if(grep -e "-a entry,always $archi -S execve" /etc/audit/audit.rules);then echo OK;else echo "-a entry,always $archi -S execve" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-a entry,never" /etc/audit/audit.rules);then echo OK;else echo "-a entry,never" >> /etc/audit/audit.rules;fi`;
#ref http://tarantule.blogspot.fr/2008/05/auditd-configuration-on-linux-to-track.html
#regle appel suid & guid hors root
$sgid=`find / -type f -perm -02000 -ls 2>/dev/null|awk '{print \$NF}'`;
@lsgid=split(/\n/,$sgid);
$iz=1;
foreach $it_ser (@lsgid){
  $ras=`if(grep -e "-a exit,always $archi -F uid!=0 -F path=$it_ser -S execve -k info_execve_suid$iz" /etc/audit/audit.rules);then echo OK;else echo "-a exit,always $archi -F uid!=0 -F path=$it_ser -S execve -k info_execve_suid$iz" >> /etc/audit/audit.rules;fi`;
  $iz=$iz+1;
}
$sgid=`find / -type f -perm -04000 -ls 2>/dev/null|awk '{print \$NF}'`;
@lsgid=split(/\n/,$sgid);
$iz=1;
foreach $it_ser (@lsgid){
  $ras=`if(grep -e "-a exit,always $archi -F uid!=0 -F path=$it_ser -S execve -k info_execve_sgid$iz" /etc/audit/audit.rules);then echo OK;else echo "-a exit,always $archi -F uid!=0 -F path=$it_ser -S execve -k info_execve_sgid$iz" >> /etc/audit/audit.rules;fi`;
  $iz=$iz+1;
}
#regle acces fichier sensible (shadow, config, contenant mot de pass en dur, config cvs, page web, ...
$ras=`if(grep -e "-w /etc/shadow -F auid!=4294967295 -p r -k info_shadow_watch" /etc/audit/audit.rules);then echo OK;else echo "-w /etc/shadow -F auid!=4294967295 -p r -k info_shadow_watch" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-w /etc/ -p wa -k info_etc_write" /etc/audit/audit.rules);then echo OK;else echo "-w /etc/ -p wa -k info_etc_write" >> /etc/audit/audit.rules;fi`;
#A permission is an action that reads (r), writes (w), executes (x), and/or changes the attribute (a) of a file
#regle SOCKET network connection hors tomoyo processus
$ras=`if(grep -e "-a exit,always $archi -S bind -F exe!=/usr/sbin/ntpd -F exe!=/usr/sbin/sshd -F exe!=/usr/sbin/rsyslogd -F exe!=/usr/sbin/nrpe -k info_bind" /etc/audit/audit.rules);then echo OK;else echo "-a exit,always $archi -S bind -F exe!=/usr/sbin/ntpd -F exe!=/usr/sbin/sshd -F exe!=/usr/sbin/rsyslogd -F exe!=/usr/sbin/nrpe -k info_bind" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-a exit,always $archi -S connect -F exe!=/usr/sbin/ntpd -F exe!=/usr/sbin/sshd -F exe!=/usr/sbin/rsyslogd -F exe!=/usr/sbin/nrpe -k info_connect" /etc/audit/audit.rules);then echo OK;else echo "-a exit,always $archi -S connect -F exe!=/usr/sbin/ntpd -F exe!=/usr/sbin/sshd -F exe!=/usr/sbin/rsyslogd -F exe!=/usr/sbin/nrpe -k info_connect" >> /etc/audit/audit.rules;fi`;
#ref:http://my.opera.com/devloop/blog/show.dml/2036593
#regle permission refusé
$ras=`if(grep -e "-a always,exit $archi -S write -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k erreur_access" /etc/audit/audit.rules);then echo OK;else echo "-a always,exit $archi -S write -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k erreur_access" >> /etc/audit/audit.rules;fi`; 
$ras=`if(grep -e "-a always,exit $archi -S write -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM  -k erreur_perm" /etc/audit/audit.rules);then echo OK;else echo "-a always,exit $archi -S write -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM  -k erreur_perm" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-a always,exit $archi -S write -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EROFS -k erreur_lecture_seul" /etc/audit/audit.rules);then echo OK;else echo "-a always,exit $archi -S write -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EROFS  -k erreur_lecture_seul" >> /etc/audit/audit.rules;fi`;
#ptrace check
$ras=`if(grep -e "-a entry,always $archi -S ptrace -k info_ptrace" /etc/audit/audit.rules);then echo OK;else echo "-a entry,always $archi -S ptrace -k info_ptrace" >> /etc/audit/audit.rules;fi`;
#delete by user
$ras=`if(grep -e "-a always,exit $archi -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -k info_delete_user" /etc/audit/audit.rules);then echo OK;else echo "-a always,exit $archi -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -k info_delete_user" >> /etc/audit/audit.rules;fi`;
#modules
$ras=`if(grep -e "-w /sbin/insmod -p x -k modules_change" /etc/audit/audit.rules);then echo OK;else echo "-w /sbin/insmod -p x -k modules_change" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-w /sbin/rmmod -p x -k modules_change" /etc/audit/audit.rules);then echo OK;else echo "-w /sbin/rmmod -p x -k modules_change" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-w /sbin/modprobe -p x -k modules_change" /etc/audit/audit.rules);then echo OK;else echo "-w /sbin/modprobe -p x -k modules_change" >> /etc/audit/audit.rules;fi`;
$ras=`if(grep -e "-a always,exit $archi -S init_module -S delete_module -k modules_change" /etc/audit/audit.rules);then echo OK;else echo "-a always,exit $archi -S init_module -S delete_module -k modules_change" >> /etc/audit/audit.rules;fi`;
#hostname configs
$ras=`if(grep -e "-a exit,always -F $archi -S sethostname -S setdomainname -k hostname_change" /etc/audit/audit.rules);then echo OK;else echo "-a exit,always -F $archi -S sethostname -S setdomainname -k hostname_change" >> /etc/audit/audit.rules;fi`;
print "Appuyer sur une touche pour continuer.";
$input = <STDIN>;
##########################################
#creation regle OSSEC
#http://dcid.me/blog/2010/03/detecting-usb-storage-usage-with-ossec/
#http://dcid.me/blog/2009/11/process-monitoring-with-ossec/
#check MAJ systeme 
#listen port changer & disk full
#http://www.ossec.net/doc/manual/monitoring/process-monitoring.html#disk-space-utilization-df-h-example
#verification processus important lancés (service)
#erreur repter sur un service (404 apache, ssh login fail, dns refused acces, ...)
#gestion des logs auditd: non modification de etc, commande sensible, socket hors service, tomoyo, action restreinte, ptrace, suid & guid access
#iptables information comportemental
#taille des logs
#statistique sur service
#utiliser les commandes de supervision nrpe pour remonter problème sur ossim
#envoyer toute log vers centrale
#ossec.net has address 150.70.191.237
print $clear_string; 
print "Installation de l'agent OSSEC...\n";
switch ($typeos) {
  case '1' { #debian
    $ras=`apt-get install -y build-essential make`;
  }
  case '2' { #centos
    $ras=`yum install -y gcc make`;
  }
}
#$ras=`iptables -t filter -A OUTPUT -p tcp --dport 80 -d www.ossec.net -j ACCEPT`;
$ras=`wget http://www.ossec.net/files/ossec-hids-2.7.tar.gz -O /root/ossec.tgz;cd /root;tar -zxf /root/ossec.tgz;cd ossec-hids-2.7`;
$command="/root/ossec-hids-2.7/install.sh";
my $exp = new Expect;
  $exp->raw_pty(1);  
  $exp->spawn($command)
    or die "Cannot spawn $command: $!\n";
$patidx = $exp->expect(10, "(en/br/cn/de/el/es/fr/hu/it/jp/nl/pl/ru/sr/tr) [en]:");
$exp->send("fr\n");
$patidx = $exp->expect(10, "Appuyez sur Entrée pour continuer ou Ctrl-C pour annuler");
$exp->send("\n");
$patidx = $exp->expect(10, "Quel type d'installation voulez-vous (serveur, agent, local ou aide)");
$exp->send("agent\n");
$patidx = $exp->expect(10, "Choisissez votre répertoire d'installation de OSSEC HIDS");
$exp->send("/opt/ossec\n");
$patidx = $exp->expect(10, "Voulez-vous démarrer le démon de vérification d'intégrité"); 
$exp->send("\n");
$patidx = $exp->expect(10, "Voulez-vous démarrer le moteur de détection de rootkit");
$exp->send("\n");
$patidx = $exp->expect(10, "voulez-vous démarrer la réponse active");
$exp->send("\n");
$patidx = $exp->expect(10, "Appuyez sur Entrée pour continuer");
$exp->send("\n");
#compilation
$patidx = $exp->expect(240, "Appuyez sur Entrée pour finir");
$exp->send("\n");
$exp->soft_close();
switch ($typeos) {
  case '1' { #debian
    $ras=`apt-get remove -y build-essential make;rm -f /root/ossec.tgz;rm -rf /root/ossec-hids-2.7`;
  }
  case '2' { #centos
    $ras=`yum remove -y gcc make;rm -f /root/ossec.tgz;rm -rf /root/ossec-hids-2.7`;
  }
}
$command="/opt/ossec/bin/manage_agents";
my $exp = new Expect;
  $exp->raw_pty(1);  
  $exp->spawn($command)
    or die "Cannot spawn $command: $!\n";
$patidx = $exp->expect(10, "Choose your action:");
$exp->send("I\n");
print "\nVeuillez entrer la clé OSSEC fourni par le serveur:";
my $keypriv = <STDIN>;
$keypriv =~ s/\n//g;
$patidx = $exp->expect(10, "Paste it here");
$exp->send($keypriv."\n");
$patidx = $exp->expect(10, "Confirm adding it?");
$exp->send("y\n");
$patidx = $exp->expect(10, "Press ENTER to return to the main menu");
$exp->send("\n");
$patidx = $exp->expect(10, "Choose your action");
$exp->send("Q\n");
$exp->soft_close();
#$ras=`iptables -t filter -D OUTPUT -p tcp --dport 80 -d www.ossec.net -j ACCEPT`;
$ras=`sed -i.bak '\$d'  /opt/ossec/etc/ossec.conf`;
$ras=`echo "  <localfile>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "    <log_format>linux_auditd</log_format>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "    <location>/var/log/audit/audit_custom.log</location>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "  </localfile>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "  <localfile>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "    <log_format>multi-line:4</log_format>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "    <location>/var/log/tomoyo/reject_003.log</location>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "  </localfile>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "    <log_format>multi-line:4</log_format>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "    <location>/var/log/tomoyo/reject_002.log</location>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "  </localfile>" >>  /opt/ossec/etc/ossec.conf`;
$ras=`echo "</ossec_config>" >>  /opt/ossec/etc/ossec.conf`;
print "\nEntrer l'adresse IP de votre serveur OSSEC:";
$ossecserv = <STDIN>;
$ossecserv =~ s/\n//g;
$ras=`sed -i.bak 's/<client>/<client>\\n    <server-ip>$ossecserv<\\/server-ip> /'  /opt/ossec/etc/ossec.conf`;
$ras=`if(grep -e "/usr/local/bin/audit.pl" /etc/rc.local);then echo OK;else /bin/echo "/usr/bin/tail -F /var/log/audit/audit.log|/usr/bin/perl /usr/local/bin/audit.pl > /var/log/audit/audit_custom.log&" >> /etc/rc.local;sed -i '/exit 0/d' /etc/rc.local;echo "exit 0" >> /etc/rc.local;fi`;
switch ($typeos){
        case '1' { #debian
	  $ras=`if(dpkg -l wget|grep -iv "Aucun paquet");then wget http://secu-fr.tuxfamily.org/lib/exe/fetch.php?media=audit.pl.gz -O /tmp/audit.pl.gz;cd /tmp;/gzip -d /tmp/audit.pl.gz;mv /tmp/audit.pl /usr/local/bin/audit.pl;else apt-get install -y wget;wget http://secu-fr.tuxfamily.org/lib/exe/fetch.php?media=audit.pl.gz -O /tmp/audit.pl.gz;cd /tmp;/gzip -d /tmp/audit.pl.gz;mv /tmp/audit.pl /usr/local/bin/audit.pl;apt-get remove -y wget;fi`;
	}
	case '2' {
	  $ras=`if(rpm -qa wget |wc -l|grep -iv "^0\$");then wget http://secu-fr.tuxfamily.org/lib/exe/fetch.php?media=audit.pl.gz -O /tmp/audit.pl.gz;cd /tmp;/gzip -d /tmp/audit.pl.gz;mv /tmp/audit.pl /usr/local/bin/audit.pl;else yum install -y wget; wget http://secu-fr.tuxfamily.org/lib/exe/fetch.php?media=audit.pl.gz -O /tmp/audit.pl.gz;cd /tmp;/gzip -d /tmp/audit.pl.gz;mv /tmp/audit.pl /usr/local/bin/audit.pl;yum remove -y wget;fi`;
	}
}
$fh = new IO::File;
$fh->open("/usr/local/bin/rotate_auditd_log.sh","w");
    print $fh <<EOF;
#!/bin/sh
/bin/ps aux|/bin/grep -i "/usr/bin/perl /usr/local/bin/audit.pl"|/usr/bin/awk '{print "/bin/kill " \$2}'|/bin/sh;/bin/sleep 1;/bin/ps aux|/bin/grep -i "/usr/bin/perl /usr/local/bin/audit.pl"|/usr/bin/awk '{print "/bin/kill -9 " \$2}'
/usr/bin/tail -F /var/log/audit/audit.log|/usr/bin/perl /usr/local/bin/audit.pl > /var/log/audit/audit_custom.log&
EOF
$fh->close();
$ras=`chmod +x /usr/local/bin/rotate_auditd_log.sh`;
$fh->open("/etc/logrotate.d/auditd","w");
    print $fh <<EOF;
/var/log/audit/audit_custom.log
{
        rotate 7
        daily
        missingok
        notifempty
        delaycompress
        compress
        postrotate
                /usr/local/bin/rotate_auditd_log.sh > /dev/null
        endscript
}
EOF
$fh->close();


#$ras=`iptables -t filter -D OUTPUT -p tcp --dport 1514 -d $ossecserv -j ACCEPT`;
$ras=`/etc/init.d/ossec restart`;
print "Appuyer sur une touche pour continuer.";
$input = <STDIN>;
##########################################
#/etc/hosts.deny et /etc/hosts.allow
print $clear_string; 
print "Mise en place de /etc/hosts.deny avec ALL: ALL...";
$ras=`if(grep -e "ALL: ALL" /etc/hosts.deny);then echo OK;else mv /etc/hosts.deny /etc/hosts.deny.old;echo "ALL: ALL" > /etc/hosts.deny;fi`;
print "OK.\nAppuyer sur une touche pour continuer.";
$input = <STDIN>;
##########################################
#Creation iptables & QOS
#http://www.netfilter.org/documentation/HOWTO/fr/netfilter-extensions-HOWTO-3.html
#tout interdire
#journaliser tout les blocages
#protection ddos, floood, poofing, ...
#creation des politiques de restriction comportemental reseau
#restriction des sorties, NTP , SSH, service, web restriction (apt/yum) + update autre service, SVN ou GIT,
#+ restrict ip, debit, interface, connexion, ... 
#qos avec TC http://wiki.linuxwall.info/doku.php/fr:ressources:dossiers:networking:qos_traffic_control & http://www.unixgarden.com/index.php/gnu-linux-magazine/qos-et-gestion-du-trafic-avec-traffic-control
#qos layer: ntp, nrpe, dns
#qos layer: ssh
print $clear_string;
my $mysshclt=""; 
print "Mise en place de règles IPTABLES stricte...\n";
print "ATTENTION si vous etes actuelement en session ssh veuillez indiquer l'IP de votre client afin de ne pas être bloqué.\n";
print "L'adresse IP client restera dans votre configuration de base ssh, si ce dernier n'est pas l'IP officiel d'acces ssh, il faudra l'enlever apres la fin d'execution du script.\n";
print "Etes vous connecté en ssh? (oui/non)";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Veuillez entrer l'IP (ou non):";
  $mysshclt = <STDIN>;
  $mysshclt =~ s/\n//g;
}
if($typeos == 1){
  $ras=`export DEBIAN_FRONTEND=noninteractive;apt-get install -y iptables-persistent libpcre3 git`;
  $ras=`cd /root;git clone https://github.com/zertrin/iptables-persistent;cp /root/iptables-persistent/iptables-persistent.conf /etc/default/iptables-persistent.conf;mv /etc/init.d/iptables-persistent /etc/init.d/iptables-persistent.orig;cp /root/iptables-persistent/iptables-persistent /etc/init.d/iptables-persistent;update-rc.d iptables-persistent defaults;rm -rf /root/iptables-persistent`;
  $ras=`apt-get remove -y git;apt-get autoremove -y`;
}
#interdire tout
$ras=`iptables -t filter -F;iptables -t filter -X`;
$ras=`iptables -t filter -P INPUT DROP;iptables -t filter -P FORWARD DROP;iptables -t filter -P OUTPUT DROP`;
#ne pas bloquer les connexions etablies
$ras=`iptables -t filter -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT;iptables -t filter -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT`;
#loopback ACCEPT
$ras=`iptables -t filter -A INPUT -i lo -j ACCEPT;iptables -t filter -A OUTPUT -o lo -j ACCEPT`;
#icmp ping
$ras=`iptables -t filter -A INPUT -p icmp -j ACCEPT;iptables -t filter -A OUTPUT -p icmp -j ACCEPT`;
#
if($mysshclt =~ /\./){ 
  $ras=`iptables -t filter -I INPUT -p tcp --dport 22 -s $mysshclt -j ACCEPT`;
  $ras=`if(grep -e "sshd: $mysshclt" /etc/hosts.allow);then echo OK; else echo "sshd: $mysshclt" >> /etc/hosts.allow;fi`;
}
#dns resolution
my $dnsservtmp=`grep -i "^nameserver" /etc/resolv.conf|sed -e 's/nameserver\\s//g'`;
@dnsserv=split(/\n/,$dnsservtmp);
foreach $dns (@dnsserv){
   if($dns =~ /\./){
    print "ADD DNS resolv: $dns dans IPTABLES...\n";
    $ras=`iptables -t filter -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT;iptables -t filter -A OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT`;
    $ras=`iptables -t mangle -A OUTPUT -p udp -d $dns --dport 53 -j MARK --set-mark 10`;
   }
}
sleep(5);
print "\nAccedez vous a vos depots de package par proxy? (Oui/Non)";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Veuillez entrer l'adresse IP de votre proxy pour l'acces a vos depots de package:";
  my $proxydep = <STDIN>;
  $proxydep =~ s/\n//g;
  print "Veuillez entrer le port d'accès de votre proxy:";
  my $pport = <STDIN>;
  $pport =~ s/\n//g;
  $ras=`iptables -t filter -A OUTPUT -p tcp --dport $pport -d $proxydep -j ACCEPT`;
} else {
  my $depotservtmp="";
  switch ($typeos) {
    case '1' { #debian
      #apt depot
      my $tmpdepot=`grep -Po "(?<=^deb\\s).*?(?=#|\$)" /etc/apt/sources.list|cut -d/ -f3`;
      my @ltmpdepot=split(/\n/,$tmpdepot);
      foreach $dlist (@ltmpdepot){
	my $iptmp=`host -t A $dlist|grep -i "has address"|awk '{print \$NF}'`;
	my @liptmp=split(/\n/,$iptmp);
	foreach $Eiptmp (@liptmp){
	  $depotservtmp=$depotservtmp."$Eiptmp\n";
	}
      }
    }
    case '2' { #centos
      #yum depot
      my $tmpdepot=`grep -vR "^#" /etc/yum.repos.d/|grep -i "http://"|cut -d: -f3|cut -d/ -f3`;
      my @ltmpdepot=split(/\n/,$tmpdepot);
      foreach $dlist (@ltmpdepot){
	my $iptmp=`host -t A $dlist|grep -i "has address"|awk '{print \$NF}'`;
	my @liptmp=split(/\n/,$iptmp);
	foreach $Eiptmp (@liptmp){
	  $depotservtmp=$depotservtmp."$Eiptmp\n";
	}
      }
    }
  }
  @depotserv=split(/\n/,$depotservtmp);
  foreach $depotip (@depotserv){
    if($depotip =~ /^[0-9]/){
      print "ADD Depot package: $depotip dans IPTABLES...\n";
      $ras=`iptables -t filter -A OUTPUT -p tcp --dport 80 -d $depotip -j ACCEPT`;
    }
  }
}
#ossec
$ras=`iptables -t filter -A OUTPUT -p udp --dport 1514 -d $ossecserv -j ACCEPT`;
$ras=`iptables -t filter -A OUTPUT -p tcp --dport 1514 -d $ossecserv -j ACCEPT`;
#syn attacks
$ras=`iptables -t filter -A INPUT -p tcp ! --syn -m state --state NEW -j DROP`;
# Drop fragments
$ras=`iptables -t filter -A INPUT -f -j DROP`;
# Drop XMAS packets
$ras=`iptables -t filter -A INPUT -p tcp --tcp-flags ALL ALL -j DROP`;
# Drop NULL packets
$ras=`iptables -t filter -A INPUT -p tcp --tcp-flags ALL NONE -j DROP`;
#DROP any invalid packet 
$ras=`iptables -t filter -A INPUT -m state --state INVALID -j DROP`;
#DROP broadcast
#get ip broadcast
$bcast=`ifconfig |grep -i "bcast:" |awk '{print \$3}'|awk -F":" '{print \$2}'`;
@bcastl=split(/\n/,$bcast);
foreach $bcast_it (@bcastl){
  $ras=`iptables -t filter -A INPUT -d $bcast_it -j DROP`;
}
#log iptables
$ras=`iptables -t filter -N LOGGING_INPUT;iptables -t filter -A INPUT -j LOGGING_INPUT`;
$ras=`iptables -t filter -A LOGGING_INPUT -p tcp -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables: [denied INPUT TCP] " --log-level 7;iptables -t filter -A LOGGING_INPUT -p udp -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables: [denied INPUT UDP] " --log-level 7;iptables -t filter -A LOGGING_INPUT -p icmp -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables: [denied INPUT ICMP] " --log-level 7`;
$ras=`iptables -t filter -N LOGGING_OUTPUT;iptables -t filter -A OUTPUT -j LOGGING_OUTPUT`;
$ras=`iptables -t filter -A LOGGING_OUTPUT -p tcp -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables: [denied OUTPUT TCP] " --log-level 7;iptables -t filter -A LOGGING_OUTPUT -p udp -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables: [denied OUTPUT UDP] " --log-level 7;iptables -t filter -A LOGGING_OUTPUT -p icmp -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables: [denied OUTPUT ICMP] " --log-level 7`;
#QOS layer 1 : ntp, snmp, dns
#QOS layer 2 : ssh, nrpe
#http://www.randco.fr/actualites/2013/qos-sous-linux/
print "Creation QOS avec TC\n";
$ras=`iptables -t mangle -A OUTPUT -p tcp -m multiport --sports 22,5666,514 -j MARK --set-mark 10`;
print "\nEntrer le nom de votre interface reseau \"public\": (ex: eth0)\n";
my $INT_PUB = <STDIN>;
$INT_PUB =~ s/\n//g;
my $cmd=`if(ifconfig $INT_PUB);then echo TESTok;else echo ko;fi`;
if ($cmd =~ /TESTok/){
    $myippub=`ifconfig $INT_PUB | grep -i "inet adr"|awk '{print \$2}'|cut -d ":" -f 2`;
    $myippub =~ s/\n//g;
    print "Votre ip privée est $myippub sur l'interface $INT_PUB\n";
} else {
    print "L'interface $INT_PUB n'existe pas.\n";
    exit 0;
}
$ras=`iptables -t mangle -A OUTPUT -p udp -m multiport --dports 123,514 -j MARK --set-mark 10`;
$ras=`dmesg | grep -i "$interfacepriv"|grep -i "link is Up"|sed -e 's/\\sMbps/Mbit/g'`;
@mbps=split(/ /,$ras);
foreach $mbits (@mbps){
  if($mbits =~ /mbit/i){
    $DEB_PRIV=$mbits;
  }
}
$ras=`dmesg | grep -i "$INT_PUB"|grep -i "link is Up"|sed -e 's/\\sMbps/Mbit/g'`;
@mbps=split(/ /,$ras);
foreach $mbits (@mbps){
  if($mbits =~ /mbit/i){
    $DEB_PUB=$mbits;
  }
}
#TODO
# Netoyage
my $INT_PRIV=$interfacepriv;
$ras=`tc qdisc del dev $interfacepriv root    >/dev/null 2>&1`;
$ras=`tc qdisc del dev $interfacepriv ingress >/dev/null 2>&1`;
$ras=`tc qdisc del dev $INT_PUB root    >/dev/null 2>&1`;
$ras=`tc qdisc del dev $INT_PUB ingress >/dev/null 2>&1`;
# Création de la classe parent:
$ras=`mv /usr/local/bin/tc.restore /usr/local/bin/tc.restore.old`;
$ras=`tc qdisc add dev $INT_PUB root handle 1: htb default 100`;
$ras=`echo "#!/bin/sh" > /usr/local/bin/tc.restore`;
$ras=`echo "tc qdisc add dev $INT_PUB root handle 1: htb default 100" >> /usr/local/bin/tc.restore`;
$ras=`tc qdisc add dev $INT_PRIV root handle 2: htb default 100`;
$ras=`echo "tc qdisc add dev $INT_PRIV root handle 2: htb default 100" >> /usr/local/bin/tc.restore`;
print "Veuillez indiquer le nombre de classe a mettre en place pour votre interface privé (min 2): $interfacepriv\n";
print "	Une classe represente une priorité pour un ou plusieurs service. On créer une priorité sur un flux grace au tag iptables, on peut tagger de la meme note differents flux.\n";
print "	Si on indique 2 classes, alors on aura une classe priorisé et une classe par defaut pour tous les autres traffic hors tag iptables.\n";
print "	iptables tag prio 1 pour ssh/nrpe/syslog/ntp service.\n";
print "Entre le nombre de classe (max 10):";
my $nbrclasspriv = <STDIN>;
$nbrclasspriv =~ s/\n//g;
if($nbrclasspriv > 10){
  $nbrclasspriv=10;
}
if($nbrclasspriv < 2){
  $nbrclasspriv=2;
}
$PRIVCLASS=$nbrclasspriv;
print "\n Vous avez un debit maximum imposé par votre carte ethernet de $DEB_PRIV.\nVoulez vous modifier le debit max? (Oui/Non)\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Veuillez indiquer le debit max (veuillez indiquer le type de debit a la suite [kbit/mbit/gbit]):\n";
  $DEB_PRIV = <STDIN>;
  $DEB_PRIV =~ s/\n//g;
  $DEB_PRIV =~ s/ //g;
}
$ras=`tc class add dev $INT_PRIV parent 2:0 classid 2:$nbrclasspriv htb rate $DEB_PRIV mtu 1500`;
$ras=`echo "tc class add dev $INT_PRIV parent 2:0 classid 2:$nbrclasspriv htb rate $DEB_PRIV mtu 1500" >> /usr/local/bin/tc.restore`;
for($i=1;$i<$nbrclasspriv;$i++){
print "Attention le total de debit max par classe ne doit pas depasser la valeur $DEB_PRIV...\n";
print "Veuillez indiquer le debit max pour la classe QOS n°$i (veuillez indiquer le type de debit a la suite [kbit/mbit/gbit]):";
my $debcl = <STDIN>;
$debcl =~ s/\n//g;
$debcl =~ s/ //g;
# Classe de limitation
$iz=$i."0";
$ras=`tc class add dev $INT_PRIV parent 2:$nbrclasspriv classid 2:$iz htb rate $debcl ceil $DEB_PRIV prio $i`;
$ras=`echo "tc class add dev $INT_PRIV parent 2:$nbrclasspriv classid 2:$iz htb rate $debcl ceil $DEB_PRIV prio $i" >> /usr/local/bin/tc.restore`;
#correspondance iptables & tc
$ras=`tc filter add dev $INT_PRIV parent 2: protocol ip prio $i handle $iz fw flowid 2:$iz`;
$ras=`echo "tc filter add dev $INT_PRIV parent 2: protocol ip prio $i handle $iz fw flowid 2:$iz" >> /usr/local/bin/tc.restore`;
}
print "Attention le total de debit max par classe ne doit pas depasser la valeur $DEB_PRIV...\n";
print "Veuillez indiquer le debit max pour la dernière classe QOS qui represente le flux par defaut (veuillez indiquer le type de debit a la suite [kbit/mbit/gbit]):";
my $debcld = <STDIN>;
$debcld =~ s/\n//g;
$debcld =~ s/ //g;
# Classe de limitation defaut
$ras=`tc class add dev $INT_PRIV parent 2:$nbrclasspriv classid 2:100 htb rate $debcld ceil $DEB_PRIV prio 10`;
$ras=`echo "tc class add dev $INT_PRIV parent 2:$nbrclasspriv classid 2:100 htb rate $debcld ceil $DEB_PRIV prio 10" >> /usr/local/bin/tc.restore`;

print "\n\nVeuillez indiquer le nombre de classe a mettre en place pour votre interface publique: $INT_PUB\n";
print "	Une classe represente une priorité pour un ou plusieurs service. On créer une priorité sur un flux grace au tag iptables, on peut tagger de la meme note differents flux.\n";
print "	Si on indique 2 classes, alors on aura une classe priorisé et une classe par defaut pour tous les autres traffic hors tag iptables.\n";
print "Entre le nombre de classe (max 10):";
my $nbrclasspriv = <STDIN>;
$nbrclasspriv =~ s/\n//g;
if($nbrclasspriv > 10){
  $nbrclasspriv=10;
}
$PUBCLASS=$nbrclasspriv;
print "\n Vous avez un debit maximum imposé par votre carte ethernet de $DEB_PUB.\nVoulez vous modifier le debit max? (Oui/Non)\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Veuillez indiquer le debit max (veuillez indiquer le type de debit a la suite [kbit/mbit/gbit]):\n";
  $DEB_PUB = <STDIN>;
  $DEB_PUB =~ s/\n//g;
  $DEB_PUB =~ s/ //g;
}
$ras=`tc class add dev $INT_PUB parent 1:0 classid 1:$nbrclasspriv htb rate $DEB_PUB mtu 1500`;
$ras=`echo "tc class add dev $INT_PUB parent 1:0 classid 1:$nbrclasspriv htb rate $DEB_PUB mtu 1500" >> /usr/local/bin/tc.restore`;
for($i=1;$i<$nbrclasspriv;$i++){
print "Attention le total de debit max par classe ne doit pas depasser la valeur $DEB_PUB...\n";
print "Veuillez indiquer le debit max pour la classe QOS n°$i (veuillez indiquer le type de debit a la suite [kbit/mbit/gbit]):";
my $debcl = <STDIN>;
$debcl =~ s/\n//g;
$debcl =~ s/ //g;
# Classe de limitation
$iz=$i."0";
$ras=`tc class add dev $INT_PUB parent 1:$nbrclasspriv classid 1:$iz htb rate $debcl ceil $DEB_PUB prio $i`;
$ras=`echo "tc class add dev $INT_PUB parent 1:$nbrclasspriv classid 1:$iz htb rate $debcl ceil $DEB_PUB prio $i" >> /usr/local/bin/tc.restore`;
#correspondance iptables & tc
$ras=`tc filter add dev $INT_PUB parent 1: protocol ip prio $i handle $iz fw flowid 1:$iz`;
$ras=`echo "tc filter add dev $INT_PUB parent 1: protocol ip prio $i handle $iz fw flowid 1:$iz" >> /usr/local/bin/tc.restore`;
}
print "Attention le total de debit max par classe ne doit pas depasser la valeur $DEB_PUB...\n";
print "Veuillez indiquer le debit max pour la dernière classe QOS qui represente le flux par defaut (veuillez indiquer le type de debit a la suite [kbit/mbit/gbit]):";
my $debcld = <STDIN>;
$debcld =~ s/\n//g;
$debcld =~ s/ //g;
# Classe de limitation defaut
$ras=`tc class add dev $INT_PUB parent 1:$nbrclasspriv classid 1:100 htb rate $debcld ceil $DEB_PUB prio 10`;
$ras=`echo "tc class add dev $INT_PUB parent 1:$nbrclasspriv classid 1:100 htb rate $debcld ceil $DEB_PUB prio 10" >> /usr/local/bin/tc.restore`;
print "Sauveguarde de la configuration TC dans: /usr/local/bin/tc.restore avec lancement a partir de /etc/rc.local\n";
$ras=`chmod +x /usr/local/bin/tc.restore`;
$ras=`if(grep -e "/usr/local/bin/tc.restore" /etc/rc.local);then echo OK;else echo "/usr/local/bin/tc.restore" >> /etc/rc.local;sed -i '/exit 0/d' /etc/rc.local;echo "exit 0" >> /etc/rc.local;fi`;
#iptables save and reload on start
switch ($typeos) {
  case '1' { #debian
    $iptablesave=`iptables-save > /etc/iptables/rules`;
    print "Sauveguarde de la configuration iptables dans: /etc/iptables/rules\n";
  }
  case '2' { #centos
    $iptablesave=`iptables-save > /etc/iptables.rules;iptables-save > /etc/sysconfig/iptables`;
  }
}
print "OK.\nAppuyer sur une touche pour continuer.";
$input = <STDIN>;
##########################################
#Installation SVN
print $clear_string; 
print "Voulez vous installer SVN? (Oui/Non)\n";
print "La subversion permet d'importer/exporter des fichiers de configuration/script et de garder une historique des modifications...\n";
print "Le mieux est d'avoir un serveur SVN ainsi qu'un serveur de config qui modifie le SVN en ecriture. Il declenche un hooks qui permettra l'ecriture des modifications sur votre serveur. Il sera donc interdit d'ecrire dans la configuration a partir du serveur afin de centraliser cette dernière.\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Installation de svn...";
  switch ($typeos) {
        case '1' { #debian
	  $ras=`/usr/bin/apt-get install -y subversion`;
	  if ($DEBUG==1){ print "$ras";}
	  #creation user svn
	  $ras=`useradd subversion -m`;
	}
        case '2' { #centos
	  $ras=`/usr/bin/yum install -y subversion`;
	  if ($DEBUG==1){ print "$ras";}
	}
  }
  print "Ok\n";
  print "Veuillez indiquer l'adresse du serveur SVN (sur interface priv):\n";
  $servsvn = <STDIN>;
  $servsvn =~ s/\n//g;
  $ras=`iptables -t filter -A OUTPUT -p tcp --dport 443 -d $servsvn -j ACCEPT`;
  print "Vous devrez penser a créer une certificat pour l'utilisateur subversion avec un passphrase et une entrée dans sudo pour la mise a jour des configs par script\n";
  print "Principe de fonctionnement: data-config -> commit -> serv HOOk post commit -> ssh subversion\@service-conf -> exec sudo command -> svn sur https -> fin\n";
  #creation regle firewall pour authorisé svn a se connecté en https sur le depot
  #creation dans ssh de l'acces a l'IP du serv SVN
  #sudo
}
print "Veuillez appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;  
##########################################
#Installation OCS ?
##########################################
#Installation service de base: ssh, ntp, nrpe, syslog
#les problème de frequence/comportement/statistique ne sont pas pris en compte dans les services d'admin
#ils sont censsé etre proteger par le reseu privé d'une attaque exterieur
#ils sont limité en accès par l'iptables & tomoyo & auditd pour des raisons de compromission interne
#network inet stream accept @LOCAL-ADDRESS 22
#TODO: ajouter cgroups memoire pour les serveur lancé avec users specifiques: ntp, nrpe
print $clear_string; 
print "Voulez vous installer le package d'admin: ssh, ntp, nrpe, syslog (Oui/Non)\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Installation de ntp...";
  switch ($typeos) {
        case '1' { #debian
	  $ras=`/usr/bin/apt-get install -y ntp`;
	  if ($DEBUG==1){ print "$ras";}
	}
        case '2' { #centos
	  $ras=`/usr/bin/yum install -y ntp`;
	  if ($DEBUG==1){ print "$ras";}
	}
  }
  print "Ok\n";
  print "Veuillez donner l'adresse IP du serveur NTP:\n";
  $NTPSERV = <STDIN>;
  $NTPSERV =~ s/\n//g;
  $ras=`mv /etc/ntp.conf /etc/ntp.conf.old`;
  open(outFILE, ">/etc/ntp.conf") or die "Impossible d'ouvrir le fichier /etc/ntp.conf";
  print outFILE "interface ignore all\ninterface listen 127.0.0.1\nserver $NTPSERV\nrestrict 127.0.0.1\nrestrict $NTPSERV mask 255.255.255.255 nomodify notrap noquery\n";
  $ras=`iptables -t filter -I OUTPUT -p udp --dport 123 -d $NTPSERV -j ACCEPT`;
  $ras=`/etc/init.d/ntp restart`;
  $ras=`if(grep -i "^initialize_domain /etc/init.d/ntp from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /etc/init.d/ntp from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /usr/sbin/ntpd from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /usr/sbin/ntpd from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
  $ras=`/etc/init.d/ntp restart`;
  $ras=`tomoyo-setprofile 1 '<kernel> /usr/sbin/ntpd'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
  $ras=`/etc/init.d/ntp restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
  $ras=`tomoyo-savepolicy`; # permet de répercuter l'apprentissage en cours de /sys/kernel/security/tomoyo/domain_policy vers /etc/tomoyo/policy/current/domain_policy.conf 
  print "Iptables active pour NTP\nTomoyo en mode apprentissage sur ntpd, pour modification des permissions voir dans /etc/tomoyo/policy/current/domain_policy.conf domaine <kernel> /usr/sbin/ntpd \nreload -> tomoyo-loadpolicy -df\n	Puis passage en profile enforce(3) ou permissif(2) avec rechargement de la policy si differente par:\n		cat /etc/tomoyo/policy/current/domain_policy.conf | tomoyo-loadpolicy -df\n";
  print "	Quand vous passerez en mode 2 ou 3, pensez a bien restreindre l'acces reseau au seul serveur NTP.\n";
  print "Vous pouvez limiter la memoire RAM & Swap utilisé par ntp grace au Cgroups. La restriction vous serez proposé après lors de la section user. (user: ntp)\n";
  #fixer interface & ip
  #creation regle firewall et auditd sur acces reseau
  #creation regle tomoyo << limitation au ressources strictement nécéssaire
  print "Installation de ssh & fail2ban...";
  #iptables save and reload on start
  switch ($typeos) {
        case '1' { #debian
	  $iptablesave=`iptables-save > /etc/iptables/rules`;
	  $ras=`/usr/bin/apt-get install -y ssh fail2ban`;
	  if ($DEBUG==1){ print "$ras";}
	}
        case '2' { #centos
	  $iptablesave=`iptables-save > /etc/iptables.rules;iptables-save > /etc/sysconfig/iptables`;
	  $ras=`/usr/bin/yum install -y openssh-server openssh-clients fail2ban`;
	  if ($DEBUG==1){ print "$ras";}
	}
  }
  print "Ok\n";
  print "Configuration SSH restrictif...\n";
  print "A configurer dans sshd.conf:\n";
  print "Veuillez entrer l'IP du client d'administration ssh...\n";
  my $IPCLTSSH = <STDIN>;
  $IPCLTSSH =~ s/\n//g;
  print "Creation d'un groupe sshusers\nTous les utilisateurs appartenant a ce groupe seront  authorisé a se connecté sur le ssh du serveur.\nAttention l'ajout des utilisateurs s'effectura plus loin, lors du traitement user...\n";
  $ras=`groupadd -r sshusers`;
  print "ATTENTION: si vous etes connecté en ssh, rajouter maintenant votre utilisateur dans le groupe sshusers: usermod -a -G sshusers votre_username\nAppuyer sur une touche pour continuer\n";
  $input = <STDIN>;
  #$ras=`usermod -a -G sshusers $user`;
  my @param = (
    "ListenAddress",
    "Protocol",
    "PermitRootLogin",
    "LoginGraceTime", 
    "AllowGroups", 
    "PasswordAuthentication",
    "ServerKeyBits",
    "IgnoreRhosts",
    "RhostsRSAAuthentication", 
    "HostbasedAuthentication",
    "PermitEmptyPasswords",
    "UsePam",
    "MaxAuthTries",
    "MaxSessions",
    "PermitTunnel",
    "DebianBanner",
    "Banner"
  );
  my @pval = (
    "$myippriv",
    "2",
    "no",# possible: without-password
    "30",
    "sshusers",
    "no",
    "2048", # ou 1024
    "yes",
    "no",
    "no",
    "no",
    "yes",
    "3",
    "2",
    "no",
    "no",
    "no"
  ); 
  #savoir si la valeur a été trouvé ou si il faut l'ajouter dans le fichier...
  my @pval_ok = (
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  );
  open(inFILE, "</etc/ssh/sshd_config") or die "Impossible d'ouvrir le fichier /etc/ssh/sshd_config";
  open(outFILE, ">/etc/ssh/sshd_config.new") or die "Impossible d'ouvrir le fichier /etc/ssh/sshd_config.new";
  my $trouve=0;
  while (<inFILE>){
    $trouve = 0;
    for($i=0;$i<=$#param;$i++){
      if ($_ =~ /^$param[$i]/i){
	print "Configuration actuel de $_\n";
	my $conf="$param[$i] $pval[$i]";
	print "Configuration mise en place: $conf\n";
	print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec $param[$i] )\n";
	  my $conftmp = <STDIN>;
	  $conftmp =~ s/\n//g;
	  print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	  $input = <STDIN>;
	  if ($input =~ /^yes/i | $input =~ /^oui/i){
	    $conf=$conftmp;
	  }
	}
	print outFILE $conf."\n";
	print outFILE "#".$_;
	$pval_ok[$i]=1;
	$trouve=1;
      }
    }
   if($trouve==0){
    print outFILE $_;
   }
  }
  for($i=0;$i<=$#param;$i++){
    if($pval_ok[$i] == 0){
      my $conf="$param[$i] $pval[$i]";
      print "Configuration mise en place: $conf\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec $param[$i] )\n";
	my $conftmp = <STDIN>;
	$conftmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $conf=$conftmp;
	}
      }
      print outFILE $conf."\n";
    }
  }   
  close inFILE;
  close outFILE;
  $ras=`mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old`;
  $ras=`mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config`;
  $ras=`/etc/init.d/ssh restart`;
  $ras=`if(grep -e "sshd: $IPCLTSSH" /etc/hosts.allow);then echo OK; else echo "sshd: $IPCLTSSH" >> /etc/hosts.allow;fi`;
  if($typeos==1){ #debian
    $ras=`/etc/init.d/iptables-persistent restart`;
    $iptablesave=`iptables-save > /etc/iptables/rules`;
  }
  $ras=`iptables -t filter -I INPUT -p tcp --dport 22 -s $IPCLTSSH -j ACCEPT`;
  if($typeos==1){ #debian
    $iptablesave=`iptables-save > /etc/iptables/rules`;
  }
  $ras=`if(grep -i "^initialize_domain /etc/init.d/ssh from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /etc/init.d/ssh from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /usr/sbin/sshd from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /usr/sbin/sshd from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /etc/init.d/fail2ban from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /etc/init.d/fail2ban from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /usr/bin/fail2ban-server from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /usr/bin/fail2ban-server from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
  $ras=`/etc/init.d/ssh restart`;
  $ras=`/etc/init.d/fail2ban restart`;
  $ras=`tomoyo-setprofile 1 '<kernel> /usr/sbin/sshd'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
  $ras=`tomoyo-setprofile 1 '<kernel> /usr/bin/fail2ban-server'`;
  $ras=`/etc/init.d/ssh restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
  $ras=`/etc/init.d/fail2ban restart`; 
  $ras=`tomoyo-savepolicy`; # permet de répercuter l'apprentissage en cours de /sys/kernel/security/tomoyo/domain_policy vers /etc/tomoyo/policy/current/domain_policy.conf 
  if($typeos==1){ #debian
    $ras=`/etc/init.d/iptables-persistent restart`;
    $iptablesave=`iptables-save > /etc/iptables/rules`;
  }
  print "Tomoyo mise en place sur sshd et fail2ban-server en mode apprentissage...\n";
  print "	Quand vous passerez en mode 2 ou 3, pensez a bien restreindre l'acces reseau aux seules IP des clients permit.\n";
  #tomoyo sur sshd et fail2ban
  #ref.:http://virologie.free.fr/documents/openSSH/ssh_configurations.html
  #fixer interface & ip
  #creation regle firewall et auditd sur acces reseau
  #creation regle tomoyo << limitation au ressources strictement nécéssaire
  print "\nInstallation de nrpe...\n";
  switch ($typeos) {
        case '1' { #debian
	  $ras=`/usr/bin/apt-get install -y nagios-nrpe-server`;
	  if ($DEBUG==1){ print "$ras";}
	}
        case '2' { #centos
	  $ras=`/usr/bin/yum install -y nagios-nrpe`;
	  if ($DEBUG==1){ print "$ras";}
	}
  }
  print "Veuillez indiquer l'adresse IP du serveur nagios requettant sur nrpe?:\n";
  $NRPESERV = <STDIN>;
  $NRPESERV =~ s/\n//g;
  open(inFILE, "</etc/nagios/nrpe.cfg") or die "Impossible d'ouvrir le fichier /etc/nagios/nrpe.cfg";
  open(outFILE, ">/etc/nagios/nrpe.cfg.new") or die "Impossible d'ouvrir le fichier /etc/nagios/nrpe.cfg.new";
  my $t1=0;
  my $t2=0;
  while (<inFILE>){
    if ($_ =~ /^server_address=/i){
      print "Configuration actuel de $_\n";
      my $conf="server_address=$myippriv";
      print "Configuration mise en place: $conf\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec server_address=)\n";
	my $conftmp = <STDIN>;
	$conftmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $conf=$conftmp;
	}
      }
      print outFILE $conf."\n";
      print outFILE "#".$_;
      $t1=1;
    }elsif($_ =~ /^allowed_hosts=/i){
      print "Configuration actuel de $_\n";
      my $conf="allowed_hosts=$NRPESERV";
      print "Configuration mise en place: $conf\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec allowed_hosts=)\n";
	my $conftmp = <STDIN>;
	$conftmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $conf=$conftmp;
	}
      }
      print outFILE $conf."\n";
      print outFILE "#".$_;
      $t2=1;
    }else {
      print outFILE $_;
    }
  }
  if($t1==0){
      my $conf="server_address=$myippriv";
      print "Configuration mise en place: $conf\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec server_address=)\n";
	my $conftmp = <STDIN>;
	$conftmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $conf=$conftmp;
	}
       }
       print outFILE $conf."\n";
  }
  if($t2==0){
      my $conf="allowed_hosts=$NRPESERV";
      print "Configuration mise en place: $conf\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec allowed_hosts=)\n";
	my $conftmp = <STDIN>;
	$conftmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $conf=$conftmp;
	}
      }
      print outFILE $conf."\n";
  }
  #create check disk
  $tdisk=`grep -v "^#" /etc/fstab|awk '{print \$1}'`;
  $tmount=`grep -v "^#" /etc/fstab|awk '{print \$2}'`;
  @disk=split(/\n/,$tdisk);
  @mount=split(/\n/,$tmount);
  for($i=0;$i<=$#mount;$i++){
    if($mount[$i] =~ /^\/$/){
      print outFILE "command[check_root]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p $disk[$i]\n";
    }
    if($mount[$i] =~ /^\/usr$/){
      print outFILE "command[check_usr]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p $disk[$i]\n";
    }
    if($mount[$i] =~ /^\/var$/){
      print outFILE "command[check_var]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p $disk[$i]\n";
    }
    if($mount[$i] =~ /^\/tmp$/){
      print outFILE "command[check_tmp]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p $disk[$i]\n";
    }
    if($mount[$i] =~ /^\/home$/){
      print outFILE "command[check_home]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p $disk[$i]\n";
    }
  }
  #create check DNS query
  print outFILE "command[check_dns]=/usr/lib/nagios/plugins/check_dns -H www.google.fr\n";
  # create check NTP serv
  print outFILE "command[check_ntp]=/usr/lib/nagios/plugins/check_ntp -H $NTPSERV\n";
  # create check_package
  print outFILE "command[check_packages]=/usr/lib/nagios/plugins/check_packages\n";
  #create check swap
  print outFILE "command[check_swap]=/usr/lib64/nagios/plugins/check_swap -w 20% -c 10%\n";
  #create check ssh 
  print outFILE "command[check_ssh]=/usr/lib/nagios/plugins/check_ssh $myippriv\n";
  #create smtp local test
  print outFILE "command[check_smtp]=/usr/lib/nagios/plugins/check_smtp -H 127.0.0.1\n";
  #create check ossec
  print outFILE "command[check_ossec]=/usr/lib64/nagios/plugins/check_procs -w 1:1 -c 1:1 -C ossec\n";
  print "Avez vous un certificat utilisé pour un de vos services? (Oui/Non):";
  $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    print "Veuillez entrer le chemin du fichier cert:";
    $certpath = <STDIN>;
    $certpath =~ s/\n//g;
    print outFILE "command[check_cert]=/usr/lib/nagios/plugins/check_cert_expire $certpath\n";
  }
  close inFILE;
  close outFILE;
  $ras=`mv /etc/nagios/nrpe.cfg /etc/nagios/nrpe.cfg.old`;
  $ras=`mv /etc/nagios/nrpe.cfg.new /etc/nagios/nrpe.cfg`;
  #fixer interface & ip
  #creation regle firewall et auditd sur acces reseau
  #creation regle tomoyo << limitation au ressources strictement nécéssaire
  print "Ok\n";
  $ras=`iptables -t filter -I INPUT -p tcp --dport 5666 -s $NRPESERV -j ACCEPT`;
  $ras=`echo "nrpe: $NRPESERV" >> /etc/hosts.allow`;
  $ras=`/etc/init.d/nagios-nrpe-server restart`;
  $ras=`if(grep -i "^initialize_domain /etc/init.d/nagios-nrpe-server from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /etc/init.d/nagios-nrpe-server from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /usr/sbin/nrpe from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /usr/sbin/nrpe from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
  $ras=`/etc/init.d/nagios-nrpe-server restart`;
  $ras=`tomoyo-setprofile 1 '<kernel> /usr/sbin/nrpe'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
  $ras=`/etc/init.d/nagios-nrpe-server restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
  $ras=`tomoyo-savepolicy`; # permet de répercuter l'apprentissage en cours de /sys/kernel/security/tomoyo/domain_policy vers /etc/tomoyo/policy/current/domain_policy.conf 
  print "Tomoyo mise en place sur nrpe en mode apprentissage...\n";
  print "	Quand vous passerez en mode 2 ou 3, pensez a bien restreindre l'acces reseau a la seul IP du serveur nagios.\n";
  print "Vous pouvez limiter la memoire RAM & Swap utilisé par nrpe grace au Cgroups. La restriction vous serez proposé après lors de la section user. (user: nagios)\n";

  print "\n\nConfiguration SYSLOG pour la communication vers serveur central (reseau privé).\nVeuillez indiquer l'adresse IP du serveur central syslog:";
  $SYSLOGSERV = <STDIN>;
  $SYSLOGSERV =~ s/\n//g;
  $line=`grep -n "/var/log/" /etc/rsyslog.conf| grep -v "^#"| head -1|cut -d ":" -f 1`;
  $line =~ s/\n//g;
  $linex=$line."i";
  $ras=`sed -i.bak '$linex\*.* \@$SYSLOGSERV\' /etc/rsyslog.conf`;
  $ras=`iptables -t filter -I OUTPUT -p tcp --dport 514 -d $SYSLOGSERV -j ACCEPT`;
  $ras=`iptables -t filter -I OUTPUT -p udp --dport 514 -d $SYSLOGSERV -j ACCEPT`;
  $ras=`/etc/init.d/rsyslog restart`;
  $ras=`if(grep -i "^initialize_domain /etc/init.d/rsyslog from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /etc/init.d/rsyslog from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /usr/sbin/rsyslogd from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /usr/sbin/rsyslogd from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
  $ras=`/etc/init.d/rsyslog restart`;
  $ras=`tomoyo-setprofile 1 '<kernel> /usr/sbin/rsyslogd'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
  $ras=`/etc/init.d/rsyslog restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
  $ras=`tomoyo-savepolicy`; # permet de répercuter l'apprentissage en cours de /sys/kernel/security/tomoyo/domain_policy vers /etc/tomoyo/policy/current/domain_policy.conf 
  print "Tomoyo mise en place sur rsyslog en mode apprentissage...\n";
  print "	Quand vous passerez en mode 2 ou 3, pensez a bien restreindre l'acces reseau a la seul IP du serveur syslog central ($SYSLOGSERV).\n";
}
print "Veuillez appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;  
##########################################
#limitation de l'envoie de mail, mettre postfix
#limitation interface, IP destination & port, limitation tomoyo, limitation des destinataire: @cnrs.fr et adresse expediter @cnrs
print $clear_string; 
print "Voulez vous limiter votre serveur local smtp et passer sous postfix (Oui/Non)\n";
print "Limitation interface, IP serveur relais, destinataire et expediteur \@mondomain.fr, tomoyo.\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  switch ($typeos) {
        case '1' { #debian
	  $ras=`export DEBIAN_FRONTEND=noninteractive;apt-get install -y postfix`;
	}
        case '2' { #centos
	  $ras=`yum install -y postfix`;
	}
  }
  print "Veuillez donner le domaine d'envoi autorisé? (mydomain.fr)";
  my $mydomain = <STDIN>;
  $mydomain =~ s/\n//g;
  print "Veuillez donner l'adresse du serveur smtp relais:";
  my $relaissmtp = <STDIN>;
  $relaissmtp =~ s/\n//g;
  $ras=`echo "$mydomain PERMIT" > /etc/postfix/nospoof ; postmap /etc/postfix/nospoof`;
  my @param = (
    "inet_interfaces =",
    "inet_protocols =",
    "smtpd_banner =",
    "relayhost =", 
    "smtpd_sender_restrictions =", 
    "smtpd_recipient_restrictions ="
  );
  my @pval = (
    " loopback-only",
    " ipv4",
    " SMTP LOCAL",
    " $relaissmtp",
    " check_sender_access hash:/etc/postfix/local_spoof, permit_mynetworks, reject",
    " check_recipient_access hash:/etc/postfix/local_spoof, permit_mynetworks, reject"
  ); 
  #savoir si la valeur a été trouvé ou si il faut l'ajouter dans le fichier...
  my @pval_ok = (
    0,
    0,
    0,
    0,
    0,
    0
  );
  my $trouve=0;
  open(inFILE, "</etc/postfix/main.cf") or die "Impossible d'ouvrir le fichier /etc/postfix/main.cf";
  open(outFILE, ">/etc/postfix/main.cf.new") or die "Impossible d'ouvrir le fichier /etc/postfix/main.cf.new";
  while (<inFILE>){
    $trouve=0;
    for($i=0;$i<=$#param;$i++){
      if ($_ =~ /^$param[$i]/i){
	print "Configuration actuel de $_\n";
	my $conf="$param[$i] $pval[$i]";
	print "Configuration mise en place: $conf\n";
	print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec $param[$i] )\n";
	  my $conftmp = <STDIN>;
	  $conftmp =~ s/\n//g;
	  print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	  $input = <STDIN>;
	  if ($input =~ /^yes/i | $input =~ /^oui/i){
	    $conf=$conftmp;
	  }
	}
	print outFILE $conf."\n";
	print outFILE "#".$_;
	$pval_ok[$i]=1;
	$trouve = 1;
      }
    } 
    if($trouve==0){
      print outFILE $_;
   }
  }
  for($i=0;$i<=$#param;$i++){
    if($pval_ok[$i] == 0){
      my $conf="$param[$i] $pval[$i]";
      print "Configuration mise en place: $conf\n";
      print "Voulez vous modifier la configuration qui sera mise en place? (Oui/Non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer la configuration a mettre en place (il doit contenir la ligne entière donc avec $param[$i] )\n";
	my $conftmp = <STDIN>;
	$conftmp =~ s/\n//g;
	print "Confirmez de mettre en place la config: $conftmp? (Oui/Non)\n";
	$input = <STDIN>;
	if ($input =~ /^yes/i | $input =~ /^oui/i){
	  $conf=$conftmp;
	}
      }
      print outFILE $conf."\n";
    }
  }   
  close inFILE;
  close outFILE;
  $ras=`echo "$mydomain PERMIT" > /etc/postfix/local_spoof;postmap /etc/postfix/local_spoof`;
  $ras=`mv /etc/postfix/main.cf /etc/postfix/main.cf.old`;
  $ras=`mv /etc/postfix/main.cf.new /etc/postfix/main.cf`;
  $ras=`iptables -t filter -A OUTPUT -p tcp --dport 25 -d $relaissmtp -j ACCEPT`;
  $ras=`iptables -t mangle -A OUTPUT -p tcp --dport 25 -j MARK --set-mark 20`;
  $ras=`/etc/init.d/postfix restart`;
  $ras=`if(grep -i "^initialize_domain /etc/init.d/postfix from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /etc/init.d/postfix from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`if(grep -i "^initialize_domain /usr/sbin/postfix from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain /usr/sbin/postfix from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
  $ras=`/etc/init.d/postfix restart`;
  $ras=`tomoyo-setprofile 1 '<kernel> /usr/sbin/postfix'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
  $ras=`/etc/init.d/postfix restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
  $ras=`tomoyo-savepolicy`; # permet de répercuter l'apprentissage en cours de /sys/kernel/security/tomoyo/domain_policy vers /etc/tomoyo/policy/current/domain_policy.conf 
  print "Tomoyo mise en place sur postfix en mode apprentissage...\n";
  print "	Quand vous passerez en mode 2 ou 3, pensez a bien restreindre l'acces reseau a la seul IP du serveur postfix central ($relaissmtp).\n";
  print "Vous pourrez limiter la memoire RAM & Swap utilisé par postfix grace au Cgroups. La restriction vous serez proposé après lors de la section user. (user: postfix)";
}
print "Veuillez appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;  
##########################################
#SSHFS ?
#http://doc.ubuntu-fr.org/sshfs & http://wiki.debian-facile.org/sshfs:partage_de_fichiers_securise_avec_sshfs
print $clear_string; 
print "Voulez vous installer le package SSHFS (Oui/Non)\n";
$input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  print "Installation de sshfs...";
  switch ($typeos) {
        case '1' { #debian
	  $ras=`/usr/bin/apt-get install -y sshfs`;
	  if ($DEBUG==1){ print "$ras";}
	}
        case '2' { #centos
	  $ras=`/usr/bin/yum install -y fuse-sshfs`;
	  if ($DEBUG==1){ print "$ras";}
	}
  }
  print "Ok\n";
  print "Vous devrez créer votre configuration sshfs avec autofs ou fstab. Penser a ajouter l'utilisateur au groupe fuse.\n Ref.:http://doc.ubuntu-fr.org/sshfs\n";

}
print "Veuillez appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;  
##########################################
#Service a installer

  #vulnerabilité possible:
    #problème memoire: solution HARDING compilation
    #problème injection commande: solution TOMOYO, restriction + auditd: command log
    #problème fichiers: TOMOYO + auditd -> creation/lecture/ecriture/supression
    #problème DOS: solution: limitation de la memoire & quota d'espace disque & supervision & revese proxy protocolaire et applicatif 
    #problème DDOS: solution firewall, detection rapide, limitation de la memoire & bande passante QOS
    #problème information: pas de versioning
    #problème information
    #choix interface  & IP et port listen
    #choix IP dest et port src dst => iptables et TC / Horaires
    #choix de lancer avec tomoyo & chroot pas d'execution du proces en root & cgroups memory si user distint
    #choix de recompilation en HARDENING: logiciel complexe, souvent avec bug de memoire, récent.
    #ajout regle auditd & ossec & cacti => statistique & comportemental & frequence
    #respect des normes protocolaire: snort, firewall, reverse proxy
    #choix config en SVN et log en rsyslog
    #choix des partitions de config (ecriture & lecture)
    #supervision du service
    #limiter l'information: app, version, information complementaire retourné par le service (ex: whois, dns, ...)
    #regle cgroups de limitation de ressources
    #case /postfix-out/i {
      #http://major.io/2013/04/14/remove-sensitive-information-from-email-headers-with-postfix/
      #header modification pour enelver information sensible: IGNORE OU REPLACE dans header_check
      #REPLACE exemple: ^(Received: .amazonaws.com.)/ REPLACE X-Cloak-$1
      # This finds and grabs "Received: host1.amazonaws.com" and replaces it with "X-Cloak-Received: host1.amazonaws.com".
      #https://posluns.com/guides/header-removal/
      #methode autorisé que et deny le reste:
      #/^((Resent-)?From|To|Cc|Date|Return-Path|Message-ID):/ OK
      #/./ IGNORE
    #case /dns/i {
    #risque Overflow et detournement hors contexte dns: solution hardening & tomoyo
    #risque DDOS: limitation interne DNS, TC, iptable 
    #risque Corruption de l'information: 
    #		- hors contexte intranet, obligation de spoofing UDP 
    #		- methode non connu possibilité du nom respect de la forme d'un packet, contenu de champs hors contexte, ou semantiquement faux (champs sans relation pouvant causé un problème de situation non géré par le code)...
    #risque d'information: scan classe resolution, dns version, TXT info, ... 
    #interne ou externe[recompile hardening]?
    #modification version
    #limitation des requetes sur un meme domaine -> tunnel, piste: http://www.bortzmeyer.org/dns-rate-limiting-and-attacks.html
    #limitation des requetes meme domaine avec sous domaine non existant => cache corruption
    #ref nist: http://csrc.nist.gov/publications/nistpubs/800-81r1/sp-800-81r1.pdf
    #case /dhcp/i {
    #risque d'usurpation: DHCP snooping
    #risque de DOS par utilisation de toute la ressources d'IP disponibles
    #


##########################################
#verification des packages installés
print $clear_string; 
sub dpkg_list {
  print "Creation de la liste des  packages debian...";
  $ras=`rm /tmp/pkg.ori* /tmp/pkg.tot* /tmp/pkg.SO /tmp/pkg.ORI /tmp/pkg.SDEP /tmp/pkg.NSDEP /tmp/dep.SO`;
  #package racine
  $ras=`/usr/bin/aptitude search ~pstandard ~pimportant ~prequired -F"%p" > /tmp/pkg.ori`;
  $ras=`/usr/bin/dpkg -l | /bin/grep -iE "^ii" | /usr/bin/awk '{print \$2}' > /tmp/pkg.tot`;
  $ras=`/bin/cp /tmp/pkg.tot /tmp/pkg.all`;
  $ras=`/bin/cat /tmp/pkg.ori | /usr/bin/awk '{print "/bin/sed -i \\\"/^"\$1"\$/d\\\" /tmp/pkg.tot"}' | /bin/sh`;
  $ras=`/bin/cat /tmp/pkg.ori | /usr/bin/awk '{print "dpkg -s "\$1"|grep -iE \\\"^Package|^depends:|^recommends:|^provides:|^breaks:\\\""}'|sh > /tmp/dep.ori`;
  $ras=`/bin/cat /tmp/pkg.tot | sed -e 's/\\([^A-Za-z0-9_]\\\)/\\\\\\1/g' | /usr/bin/awk '{print "if(grep -iE \\\"(\\s+)"\$1"(\\s+|\\\\n|\$|,)\\\" /tmp/dep.ori);then echo \\\"Dep:"\$1"\\\" ;else echo \\\"No Dep:"\$1"\\\";fi"}'|sh|grep -i "^Dep:"|sed -e 's/^Dep://g' | sed -e 's/\\\\//g' > /tmp/pkg.ori2`;
  $ras=`cp /tmp/pkg.tot /tmp/pkg.tot2`;
  $ras=`/bin/cat /tmp/pkg.ori2 | /usr/bin/awk '{print "/bin/sed -i \\\"/^"\$1"\$/d\\\" /tmp/pkg.tot2"}' | /bin/sh`;
  $i=1;
  $z=i;
  print "Trie des packages sur dependances origine...";
  while(1){
    $i=$i + 1;
    $z=$i + 1;
    $ras=`/bin/cat /tmp/pkg.ori$i | /usr/bin/awk '{print "dpkg -s "\$1"|grep -iE \\\"^depends:|^breaks:\\\""}'|sh > /tmp/dep.ori$z`;
    $ras=`/bin/cat /tmp/pkg.tot$i | sed -e 's/\\([^A-Za-z0-9_]\\\)/\\\\\\1/g' | /usr/bin/awk '{print "if(grep -iE \\\"(\\s+)"\$1"(\\s+|\\\\n|\$|,)\\\" /tmp/dep.ori'$z');then echo \\\"Dep:"\$1"\\\" ;else echo \\\"No Dep:"\$1"\\\";fi"}' |sh|grep -i "^Dep:"|sed -e 's/^Dep://g' | sed -e 's/\\\\//g' > /tmp/pkg.ori$z`;
    if( -s "/tmp/pkg.ori$z"){ 
      $ras=`cp /tmp/pkg.tot$i /tmp/pkg.tot$z`;
      $ras=`/bin/cat /tmp/pkg.ori$z | /usr/bin/awk '{print "/bin/sed -i \\\"/^"\$1"\$/d\\\" /tmp/pkg.tot'$z'"}'| /bin/sh`;
    }else{
      $ras=`cat /tmp/pkg.ori* >> /tmp/pkg.ORI`;
      $ras=`cp /tmp/pkg.tot$i /tmp/pkg.SO`;
      last;
    }
  }
  print "Trie des packages sur dependances autres...";
  $ras=`/bin/cat /tmp/pkg.SO | /usr/bin/awk '{print "dpkg -s "\$1"|grep -iE \\\"^depends:|^breaks:|^recommends:|^provides:\\\""}'|sh > /tmp/dep.SO`;
  $ras=`/bin/cat /tmp/pkg.SO | sed -e 's/\\([^A-Za-z0-9_]\\\)/\\\\\\1/g' | /usr/bin/awk '{print "if(grep -iE \\\"(\\s+)"\$1"(\\s+|\\\\n|\$|,)\\\" /tmp/dep.SO);then echo \\\"Dep:"\$1"\\\" ;else echo \\\"No Dep:"\$1"\\\";fi"}' |sh|grep -i "^No Dep:"|sed -e 's/^No Dep://g' | sed -e 's/\\\\//g' > /tmp/pkg.SDEP`;
  $ras=`/bin/cat /tmp/pkg.SO | sed -e 's/\\([^A-Za-z0-9_]\\\)/\\\\\\1/g' | /usr/bin/awk '{print "if(grep -iE \\\"(\\s+)"\$1"(\\s+|\\\\n|\$|,)\\\" /tmp/dep.SO);then echo \\\"Dep:"\$1"\\\" ;else echo \\\"No Dep:"\$1"\\\";fi"}' |sh|grep -i "^Dep:"|sed -e 's/^Dep://g' | sed -e 's/\\\\//g' > /tmp/pkg.NSDEP`;
  print "OK\n";
##!/bin/sh
##clean
#rm /tmp/pkg.ori* /tmp/pkg.tot* /tmp/pkg.SO /tmp/pkg.ORI /tmp/pkg.SDEP /tmp/dep.SO
##package racine
#/usr/bin/aptitude search ~pstandard ~pimportant ~prequired -F"%p" > /tmp/pkg.ori
#/usr/bin/dpkg -l | /bin/grep -iE "^ii" | /usr/bin/awk '{print $2}' > /tmp/pkg.tot
#/bin/cp /tmp/pkg.tot /tmp/pkg.all
#/bin/cat /tmp/pkg.ori | /usr/bin/awk '{print "/bin/sed -i \"/^"$1"$/d\" /tmp/pkg.tot"}' | /bin/sh
#/bin/cat /tmp/pkg.ori | /usr/bin/awk '{print "dpkg -s "$1"|grep -iE \"^Package|^depends:|^recommends:|^provides:|^breaks:\""}'|sh > /tmp/dep.ori
#/bin/cat /tmp/pkg.tot | sed -e 's/\([^A-Za-z0-9_]\)/\\\1/g' | /usr/bin/awk '{print "if(grep -iE \"(\s+)"$1"(\s+|\\n|$|,)\" /tmp/dep.ori);then echo \"Dep:"$1"\" ;else echo \"No Dep:"$1"\";fi"}'|sh|grep -i "^Dep:"|sed -e 's/^Dep://g' | sed -e 's/\\//g' > /tmp/pkg.ori2
#cp /tmp/pkg.tot /tmp/pkg.tot2
#/bin/cat /tmp/pkg.ori2 | /usr/bin/awk '{print "/bin/sed -i \"/^"$1"$/d\" /tmp/pkg.tot2"}' | /bin/sh
#i=1
#z=i
#while [ 1 ]; do
#  i=$(($i + 1))
#  z=$(($i + 1))
#  /bin/cat /tmp/pkg.ori$i | /usr/bin/awk '{print "dpkg -s "$1"|grep -iE \"^depends:|^breaks:\""}'|sh > /tmp/dep.ori$z
#  /bin/cat /tmp/pkg.tot$i | sed -e 's/\([^A-Za-z0-9_]\)/\\\1/g' | /usr/bin/awk '{print "if(grep -iE \"(\s+)"$1"(\s+|\\n|$|,)\" /tmp/dep.ori'$z');then echo \"Dep:"$1"\" ;else echo \"No Dep:"$1"\";fi"}' |sh|grep -i "^Dep:"|sed -e 's/^Dep://g' | sed -e 's/\\//g' > /tmp/pkg.ori$z
#   if [ -s /tmp/pkg.ori$z ] 
#   then
#    cp /tmp/pkg.tot$i /tmp/pkg.tot$z
#    /bin/cat /tmp/pkg.ori$z | /usr/bin/awk '{print "/bin/sed -i \"/^"$1"$/d\" /tmp/pkg.tot'$z'"}'| /bin/sh
#   else
#    cat /tmp/pkg.ori* >> /tmp/pkg.ORI 
#    cp /tmp/pkg.tot$i /tmp/pkg.SO
#    break
#  fi
#done
#/bin/cat /tmp/pkg.SO | /usr/bin/awk '{print "dpkg -s "$1"|grep -iE \"^depends:|^breaks:|^recommends:|^provides:\""}'|sh > /tmp/dep.SO
#/bin/cat /tmp/pkg.SO | sed -e 's/\([^A-Za-z0-9_]\)/\\\1/g' | /usr/bin/awk '{print "if(grep -iE \"(\s+)"$1"(\s+|\\n|$|,)\" /tmp/dep.sod);then echo \"Dep:"$1"\" ;else echo \"No Dep:"$1"\";fi"}' |sh|grep -i "^No Dep:"|sed -e 's/^No Dep://g' | sed -e 's/\\//g' > /tmp/pkg.SDEP
}

sub dpkg_info {
  #variable interne
  my(@args) = @_;
  my $pkg_tmp = $args[0];
  $pkg_tmp =~ s/\n//g; # traitement des packages sans dependance et ne venant pas de l'origine une par un
  my $info_tmp;
  #information sur package SDEP
  #bash :dpkg -s nano|sed -e ':z;N;s/\n\s/||/;bz'|grep -iE "^package:|^Section:|^Description:"|sed -e 's/||/\n /g'
  $info_tmp=`dpkg -s $pkg_tmp|sed -e ':z;N;s/\\n\\s/||/;bz'|grep -iE "^package:|^Section:|^Description:"|sed -e 's/||/\\n /g'`;
  print "$info_tmp\n";
}

sub dpkg_verif_dep {
  #variable interne
  my(@args) = @_;
  my $pkg_tmp = $args[0];
  $pkg_tmp =~ s/\n//g; # traitement des packages sans dependance et ne venant pas de l'origine une par un
  my $ret_tmp=0; # no dep = 1 | dep = 0
  my $ret_cmd; # retour command call
  #verification qu'il n'y a pas de dependence
  $ret_cmd=`echo "n" > /tmp/inputtmp`;
  $ret_cmd=`apt-get remove $pkg_tmp < /tmp/inputtmp`;
  if($ret_cmd =~ /1 à enlever/i || $ret_cmd =~ /1 to remove/i){
    $ret_tmp=1;
  }
  $ret_cmd=`rm /tmp/inputtmp`;
  return $ret_tmp;
}

sub dpkg_remove {
  #variable interne
  my(@args) = @_;
  my $pkg_tmp = $args[0];
  $pkg_tmp =~ s/\n//g;# traitement des packages sans dependance et ne venant pas de l'origine une par un
  my $input; # valid delete: oui/non ou yes/no
  my $ret_tmp=0; # 0 = no delete; 1= deleted
  my $delete; # demande si il veut supprimer le package...
  my $verif; # no dep = 1 | dep = 0
  #verification qu'il n'y a pas de dependence
  $verif=dpkg_verif_dep($pkg_tmp);
  if($verif == 1){
    #Voulez vous le supprimer y/n
    print "Voulez vous supprimer le package: $pkg_tmp ? (oui/non)\n";
    $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      #etes vous sur ?
      print "Vous allez proceder a la suppression du $pkg_tmp. Etes vous sur ? (oui/non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	#suppression
	$ras=`apt-get remove -y $pkg_tmp`;
	$ras=`apt-get autoremove -y`;
	$ras=`apt-get clean -y`;
	$ras=`/bin/sed -i.bak '/$pkg_tmp/d' /tmp/pkg.ORI`;
	$ras=`/bin/sed -i.bak '/$pkg_tmp/d' /tmp/pkg.NSDEP`;
	$ras=`/bin/sed -i.bak '/$pkg_tmp/d' /tmp/pkg.SDEP`;
	$pkg_ori =~ s/\s*$pkg_tmp\s*/ /i;
	$pkg_nodep =~ s/\s*$pkg_tmp\s*/ /i;
	$pkg_dep =~ s/\s*$pkg_tmp\s*/ /i;
	return 1;
      }
    }
  } else {
    print "Impossible de supprimer $pkg_tmp car il permet a d'autre(s) package(s) d'etre present(ou alors il n'existe pas)...\n";
  }
  return $ret_tmp;
}

sub rpm_info {
  #variable interne
  my(@args) = @_;
  my $rpm_tmp = $args[0];
  $rmp_tmp =~ s/\n//g;# traitement des packages sans dependance et ne venant pas de l'origine une par un
  my $info_tmp;
  #information sur package SDEP
  print "Information sur package: $rpm_tmp\n";
  $info_tmp=`/bin/rpm -qi $rpm_tmp | grep -iE "^Group\\s*:"`;
  print "$info_tmp\n";
  $info_tmp=`/bin/rpm -qi $rpm_tmp | grep -iA10 "^Description\\s*:"`;
  print "$info_tmp\n";
  #name package & section
}
sub rpm_verif_dep {
  #variable interne
  my(@args) = @_;
  my $rpm_tmp = $args[0];
  $rmp_tmp =~ s/\n//g; # traitement des packages sans dependance et ne venant pas de l'origine une par un
  my $ret_tmp=0; # no dep = 1 | dep = 0
  my $ret_cmd; # retour command call
  #verification qu'il n'y a pas de dependence
  $ret_cmd=`/bin/rpm -q --provides $rpm_tmp|/usr/bin/wc -l`;
  if($ret_cmd == 1){
    $ret_tmp=1;
  }
  $ret_cmd=`rm /tmp/inputtmp`;
  return $ret_tmp;
}

sub rpm_remove {
  #variable interne
  my(@args) = @_;
  my $rpm_tmp = $args[0];
  $rmp_tmp =~ s/\n//g; # traitement des packages sans dependance et ne venant pas de l'origine une par un
  my $input; # valid delete: oui/non ou yes/no
  my $ret_tmp=0; # 0 = no delete; 1= deleted
  my $delete; # demande si il veut supprimer le package...
  my $verif; # no dep = 1 | dep = 0
  #verification qu'il n'y a pas de dependence
  $verif=rpm_verif_dep($rpm_tmp);
  if($verif == 1){
    #Voulez vous le supprimer y/n
    print "Voulez vous supprimer le package: $rpm_tmp ? (oui/non)\n";
    $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      #etes vous sur ?
      print "Vous allez proceder a la suppression du $rpm_tmp. Etes vous sur ? (oui/non)\n";
      $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	#suppression
	$ras=`/bin/rpm -e $rpm_tmp`;
	$ras=`/usr/bin/yum autoremove -y`;
	$ras=`/usr/bin/yum clean -y`;
	$ras=`/bin/sed -i.bak '/$rpm_tmp/d' /tmp/pkg.ori`;
	$ras=`/bin/sed -i.bak '/$rpm_tmp/d' /tmp/pkg.tot`;
	$pkg_ori =~ s/\s*$rpm_tmp\s*/ /i;
	$pkg_nodep =~ s/\s*$rpm_tmp\s*/ /i;
	return 1;
      }
    }
  } else {
    print "Impossible de supprimer $rpm_tmp car il permet a d'autre(s) package(s) d'etre present(ou alors il n'existe pas)...\n";
  }
  return $ret_tmp;
}

print "Verification des packages installés...";
switch ($typeos) {
        case '1' { #debian ; install apt-file
	  # http://forums.debian.net/viewtopic.php?f=17&t=45804 tasksel -t --new-install --task-packages standard & aptitude search ~pstandard ~pimportant ~prequired -F"%p" 
	  # apt-file ou dpkg -L ou dpkg-query -S
	  #dpkg -s package # pour info Essential: yes Status: install ok installed Priority: required Section: devel
	  dpkg_list();
	  $pkg_md5=`debsums 2>/dev/null|grep -i "FAILED"|awk '{print "echo \\\"File md5 Failed:"\$1" dans package: \`dpkg -S \"\$1\"|cut -d \\\" \\\" -f 1|sed -e \\\"s/://g\\\"\`\\\""}'|sh`;
	  $pkg_ori=`/bin/cat /tmp/pkg.ORI|tr -d '\\ \\t'|tr '\\n' ' '`;
	  $pkg_nodep=`/bin/cat /tmp/pkg.SDEP|tr -d '\\ \\t'|tr '\\n' ' '`;
	  $pkg_dep=`/bin/cat /tmp/pkg.NSDEP|tr -d '\\ \\t'|tr '\\n' ' '`;
          print "Attention sous Debian la liste des packages installé d'origine et après peut etre legèrement erronné a cause des packs de langages (manpages-fr, aspell-fr...).\n";
	  print "La liste des packages installés depuis l'instalation de base du systeme: /tmp/pkg.ORI et /tmp/pkg.SDEP\n";
	  print "ATTENTION, vous allez avoir le choix de supprimer des packages inutiles, ou pouvant aider un intru a exploiter votre système.\nLe choix de suppression se restreint au package non dependant et installé après une installation de base minimal.\n";
          print "Les éléments interessants a supprimer: developpement [compilateur], echange [wget, irc, curl, ...], ...\n";
	  print "Voici la liste des packages d'origine, certains peuvent etre dangereux pour votre système (wget, dev...). Si vous n'en n'avez pas besoin merci de les supprimers:\n";
	  while(1){	
	    print "Pakages d'origines: $pkg_ori \n";
	    print "Packages contenant un problème de SIG md5: $pkg_md5\n";
	    print "Veuillez entrer le nom du package à supprimer ou quit: ";
	    my $input = <STDIN>;
	    if ($input =~ /^quit$/i){	
	      last;
	    } else {
	      print $clear_string; #clearscreen
	      dpkg_info($input);
	      dpkg_remove($input);
	    }
	  }
	  print "Voici la liste des packages avec dependance(s) installés après le systeme de base, certains peuvent etre dangereux pour votre système (wget, dev...). Si vous n'en n'avez pas besoin merci de les supprimers:\n";
	  while(1){	
	    print "Packages avec dependance(s) installés après: $pkg_dep\n";
	    print "Packages contenant un problème de SIG md5: $pkg_md5\n";
	    print "Veuillez entrer le nom du package à supprimer ou quit: ";
	    my $input = <STDIN>;
	    if ($input =~ /^quit$/i){	
	      last;
	    } else {
	      print $clear_string; #clearscreen
	      dpkg_info($input);
	      dpkg_remove($input);
	    }
	  }
	  print "Voici la liste des packages installés après le système de base et sans dépendance, certains peuvent etre dangereux pour votre système (wget, dev...). Si vous n'en n'avez pas besoin merci de les supprimers:\n";
	  while(1){	
	    print "Pakages sans dependance installés après: $pkg_nodep\n";
	    print "Packages contenant un problème de SIG md5: $pkg_md5\n";
	    print "Veuillez entrer le nom du package à supprimer ou quit: ";
	    my $input = <STDIN>;
	    if ($input =~ /^quit$/i){	
	      last;
	    } else {
	      print $clear_string; #clearscreen
	      dpkg_info($input);
	      dpkg_remove($input);
	    }
	  }
	}
        case '2' { #centos
	  # root/install.log << packages installes de base
	  # liste fichier rpm -ql
	  if(!(-e "/root/install.log")) {
	    print "Le fichier /root/install.log n'est pas present... Le script ne peut pas fonctionner sans. Désolé!\n";
	    exit;
	  }
	  $ras=`/bin/cat /root/install.log | /bin/awk '{print \$3}'|/bin/sed -e 's/[0-9]*://g'|/bin/sed -e 's/[^a-z\\-]*//ig'|/bin/awk -F "--" '{print \$1}' |/bin/sed -e 's/-el[a-z]\$//ig'> /tmp/pkg.ori`;
	  $ras=`/bin/rpm -qa |/bin/sed -e 's/[^a-z\\-]*//ig'|/bin/awk -F "--" '{print \$1}'  |/bin/sed -e 's/-el\$//ig' > /tmp/pkg.tot`;
	  $ras=`/bin/cat /tmp/pkg.ori | /bin/awk '{print "/bin/sed -i \\\"/^"\$1"\$/d\\\" /tmp/pkg.tot"}' | /bin/sh`;
	  $pkg_ori=`/bin/cat /tmp/pkg.ori|tr '\\n' ' '`;
	  $pkg_nodep=`/bin/cat /tmp/pkg.tot|tr '\\n' ' '`;
	  $pkg_md5=`rpm -Va --nomtime --nosize --nomd5 2>/dev/null`;
	  print "OK\nLa liste des packages installés depuis l'instalation de base du systeme: /tmp/pkg.ori et /tmp/pkg.tot\n";
	  print "ATTENTION, vous allez avoir le choix de supprimer des packages inutiles, ou pouvant aider un intru a exploiter votre système.\nLe choix de suppression se restreint au package non dependant et installé après une installation de base minimal.\n";
          print "Les éléments interessants a supprimer: developpement [compilateur], echange [wget, irc, curl, ...], ...\n";
	  print "Voici la liste des packages d'origine, certains peuvent etre dangereux pour votre système (wget, dev...). Si vous n'en n'avez pas besoin merci de les supprimers:\n";
	  while(1){	
	    print "Pakages d'origines: $pkg_ori \n";
	    print "Packages contenant un problème de SIG md5:\n $pkg_md5\n";
	    print " **\"c\" == config file ;  M == file's mode ; 5 == MD5chsum failed ; D == file's major and minor numbers.L == symbolic link.U == owner file.G == group file.**\n";
	    print "Veuillez entrer le nom du package à supprimer ou quit: ";
	    my $input = <STDIN>;
	    if ($input =~ /^quit$/i){	
	      last;
	    } else {
	      print $clear_string; #clearscreen
	      rpm_info($input);
	      rpm_remove($input);
	    }
	  }
	  print "Voici la liste des packages installés après le système de base et sans dépendance, certains peuvent etre dangereux pour votre système (wget, dev...). Si vous n'en n'avez pas besoin merci de les supprimers:\n";
	  while(1){	
	    print "Pakages sans dependance installés après: $pkg_nodep\n";
	    print "Packages contenant un problème de SIG md5:\n $pkg_md5\n";
	    print " **\"c\" == config file ;  M == file's mode ; 5 == MD5chsum failed ; D == file's major and minor numbers.L == symbolic link.U == owner file.G == group file.**\n";
	    print "Veuillez entrer le nom du package à supprimer ou quit: ";
	    my $input = <STDIN>;
	    if ($input =~ /^quit$/i){	
	      last;
	    } else {
	      print $clear_string; #clearscreen
	      rpm_info($input);
	      rpm_remove($input);
	    }
	  }
	}
}
#print "Recherche des logiciels installé hors packages présents dans usr, etc, ...";
#aptitude search/purge ?config-files
#find /usr/ \( -wholename '/usr/local' -prune -o -wholename '/usr/lib/locale' -prune -o -wholename '/usr/share' \) -prune -o -type f -not -iname "*.pyc" -print 2>/dev/null | xargs rpm -qf | grep -i "aucun paquetage"
#find /usr/ \( -wholename '/usr/local' -prune -o -wholename '/usr/lib/locale' -prune -o -wholename '/usr/share' \) -prune -o -type f -not -iname "*.pyc" -print 2>/dev/null | awk -F "/" '{print "if(dpkg -S "$NF" 2>/dev/null|grep -i \""$0"$\");then echo \""$0" OK\";else echo \""$0" KO\";fi"}'|sh|grep -E "\sKO$"
#find /etc/ -type f -not -iname *.rpmnew -not -iname *.rpmsave -print 2>/dev/null | xargs rpm -qf | grep -i "aucun paquetage"
#find /etc/ -type f -print 2>/dev/null | awk -F "/" '{print "if(dpkg -S "$NF" 2>/dev/null|grep -i \""$0"$\");then echo \""$0" OK\";else echo \""$0" KO\";fi"}'|sh|grep -E "\sKO$"
#print "Recherche package contenant processus lancé... & deamon rc & crontab";
#find /etc/init.d/ -type f -print 2>/dev/null | awk -F "/" '{print "if(dpkg -S "$NF" 2>/dev/null|grep -i \""$0"$\");then echo \""$0" OK\";else echo \""$0" KO\";fi"}'|sh
#find /etc/init.d/ -type f -not -iname *.rpmnew -not -iname *.rpmsave -print 2>/dev/null | xargs rpm -qf | grep -i "aucun paquetage"
##########################################
#check kernel  ------ Surface d'attaque
#check tool readelf
print $clear_string; #clearscreen
print "Kernel verification...\n";
#Make the addresses of mmap base, heap(si kernel.randomize_va_space = 2), stack and VDSO page randomized
my $aslr=`/sbin/sysctl "kernel.randomize_va_space"| cut -d " " -f 3`;
if($aslr eq ""){
  print "problème pour connaitre ASLR...\n"
} elsif($aslr =~ /0/){
  print " ASLR...: niveau $aslr ->  no addresses randomized...\n";
  #demande d'activation
  print "Voulez vous activer l'ASLR? (oui/non) : ";
  $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    $ras=`/sbin/sysctl -w "kernel.randomize_va_space=2"`;
    $ras=`if(grep -i "^\\s*kernel.randomize_va_space\\s*=" /etc/sysctl.conf);then sed -i.bak 's/^\\s*kernel.randomize_va_space\\s*=\\s*[0-9]*/kernel.randomize_va_space=2/g' /etc/sysctl.conf;else echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf;fi`;
  }
}elsif($aslr =~ /1/) {
  print " ASLR...: niveau $aslr ->  addresses of mmap base, stack and VDSO page randomized.\n";
  print "Voulez vous activer l'ASLR niveau 2 (+heap randomized)? (oui/non) : ";
  $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    $ras=`/sbin/sysctl -w "kernel.randomize_va_space=2"`;
    $ras=`if(grep -i "^\\s*kernel.randomize_va_space\\s*=" /etc/sysctl.conf);then sed -i.bak 's/^\\s*kernel.randomize_va_space\\s*=\\s*[0-9]*/kernel.randomize_va_space=2/g' /etc/sysctl.conf;else echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf;fi`;
  }
}elsif($aslr =~ /2/) {
  print " ASLR...: niveau $aslr ->  addresses of mmap base, heap, stack and VDSO page randomized.\n";
}else{
  print " ASLR...: niveau $aslr -> non connu.\n";
}
if($typeos eq 2) {
  my $noex=`/sbin/sysctl "kernel.exec-shield"| cut -d " " -f 3`;
  if($noex eq ""){
    print "problème pour connaitre No execution memory seg...\n"
  } elsif($noex =~ /0/){
    print " Execute shield (NX protection sur CentOS equivalent GCC stack protector support)...: Disabled\n";
    print "Voulez vous activer l'ASLR? (oui/non) : ";
    $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      $ras=`/sbin/sysctl -w "kernel.exec-shield=1"`;
      $ras=`if(grep -i "^\\s*kernel.exec-shield\\s*=" /etc/sysctl.conf);then sed -i.bak 's/^\\s*kernel.exec-shield\\s*=\\s*[0-9]*/kernel.exec-shield=1/g' /etc/sysctl.conf;else echo "kernel.exec-shield=1" >> /etc/sysctl.conf;fi`;
    }
  }elsif($noex =~ /1/) {
    print " Execute shield (NX protection sur CentOS equivalent GCC stack protector support)...: Enabled\n"
  }
}
print "Appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;
print " Checksec --kernel...:\n";
#http://www.trapkit.de/tools/checksec.html
#install http://www.trapkit.de/tools/checksec.sh dans /usr/local/bin/
switch ($typeos){
        case '1' { #debian
	  $ras=`iptables -t filter -A OUTPUT -p tcp --dport 80 -d www.trapkit.de -j ACCEPT`;
	  $ras=`if(dpkg -l wget|grep -iv "Aucun paquet");then wget http://www.trapkit.de/tools/checksec.sh -O /usr/local/bin/checksec.sh 2>/dev/null; chmod +x /usr/local/bin/checksec.sh;else apt-get install -y wget;wget http://www.trapkit.de/tools/checksec.sh -O /usr/local/bin/checksec.sh 2>/dev/null; chmod +x /usr/local/bin/checksec.sh;apt-get remove -y wget;fi`;
	  $ras=`apt-get install -y binutils 2> /dev/null`;
	  $ras=`apt-get install -y lsof 2> /dev/null`;
	  $ras=`iptables -t filter -D OUTPUT -p tcp --dport 80 -d www.trapkit.de -j ACCEPT`;
	}
	case '2' {
	  $ras=`iptables -t filter -A OUTPUT -p tcp --dport 80 -d www.trapkit.de -j ACCEPT`;
	  $ras=`if(rpm -qa wget |wc -l|grep -iv "^0\$");then wget http://www.trapkit.de/tools/checksec.sh -O /usr/local/bin/checksec.sh 2>/dev/null; chmod +x /usr/local/bin/checksec.sh;else yum install -y wget;wget http://www.trapkit.de/tools/checksec.sh -O /usr/local/bin/checksec.sh 2>/dev/null; chmod +x /usr/local/bin/checksec.sh;yum remove -y wget;fi`;
	  $ras=`iptables -t filter -D OUTPUT -p tcp --dport 80 -d www.trapkit.de -j ACCEPT`;
	}
}
my $checksec=`/usr/local/bin/checksec.sh --kernel`;
print "$checksec\n";
print "Appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;
my @list_sysctl = (
"net.ipv4.conf.all.proxy_arp", #refuser la prise en charge des requetes arp pour d'autres hotes
"net.ipv4.icmp_echo_ignore_broadcasts",  # Ignorer les messages de diffusion ICMP
"net.ipv4.icmp_ignore_bogus_error_responses", # Ignorer les mauvais messages d'erreurs ICMP
"net.ipv4.icmp_ignore_bogus_error_messages", # Ignorer les mauvais messages d'erreurs ICMP
"net.ipv4.tcp_syncookies", # protection contre attaque Syn Flood
"net.ipv4.conf.all.log_martians", #Journaliser les adresses sources falsifiées ou non routables
"net.ipv4.conf.default.log_martians", #Journaliser les adresses sources falsifiées ou non routables
"net.ipv4.conf.all.accept_source_route", #Refuser le routage source
"net.ipv4.conf.default.accept_source_route", #Refuser le routage source
"net.ipv4.conf.all.rp_filter", #Refuser les adresses sources falsifiées ou non routables (spoofing)
"net.ipv4.conf.default.rp_filter", #Refuser les adresses sources falsifiées ou non routables (spoofing)
"net.ipv4.conf.all.accept_redirects", #Refuser les messages ICMP redirect
"net.ipv4.conf.default.accept_redirects", #Refuser les messages ICMP redirect
"net.ipv4.conf.all.secure_redirects", # Refuse ICMP redirects only for gateways listed in our default
"net.ipv4.conf.default.secure_redirects", # Refuse ICMP redirects only for gateways listed in our default
"net.ipv4.ip_forward", # Désactiver IP forwarding
"net.ipv4.conf.all.send_redirects", # Refuser l'emission de message ICMP redirect
"net.ipv4.conf.default.send_redirects", # Refuser l'emission de message ICMP redirect
"net.ipv6.conf.default.router_solicitations", # ????
"net.ipv6.conf.default.accept_ra_rtr_pref", #Desactivation du traitement des RA
"net.ipv6.conf.default.accept_ra_pinfo", #Desactivation du traitement des RA
"net.ipv6.conf.default.accept_ra_defrtr", #Desactivation du traitement des RA
"net.ipv6.conf.default.autoconf", # Desactiver l'auto configuration
"net.ipv6.conf.default.dad_transmits", # ???
"net.ipv6.conf.default.max_addresses", # ????
"net.ipv4.ip_local_port_range", # Rang de port local
"net.ipv4.tcp_fin_timeout",# définit le délai par défaut d'une connexion TCP/IP default 60 -> 30
"fs.file-max", # limitation du nombre de fichier ouvert
"kernel.pid_max", # valeur max de PID
"kernel.modules_disabled",
"net.ipv6.conf.all.disable_ipv6"
);
my @list_sysctl_val = (
"0",
"1",
"1",
"1",
"1",
"1",
"1",
"0",
"0",
"1",
"1",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"0",
"1",
"2000 65000",
"30",
"65535",
"65536",
"1",
"1"
); 
my @list_sysctl_desc = (
"refuser la prise en charge des requetes arp pour d'autres hotes",
"Ignorer les messages de diffusion ICMP",
"Ignorer les mauvais messages d'erreurs ICMP",
"Ignorer les mauvais messages d'erreurs ICMP",
"protection contre attaque Syn Flood",
"Journaliser les adresses sources falsifiées ou non routables",
"Journaliser les adresses sources falsifiées ou non routables",
"Refuser le routage source",
"Refuser le routage source",
"Refuser les adresses sources falsifiées ou non routables (spoofing)",
"Refuser les adresses sources falsifiées ou non routables (spoofing)",
"Refuser les messages ICMP redirect",
"Refuser les messages ICMP redirect",
"Refuse ICMP redirects only for gateways listed in our default",
"Refuse ICMP redirects only for gateways listed in our default",
"Désactiver IP forwarding",
"Refuser l'emission de message ICMP redirect",
"Refuser l'emission de message ICMP redirect",
"????",
"Desactivation du traitement des RA",
"Desactivation du traitement des RA",
"Desactivation du traitement des RA",
"Desactiver l'auto configuration",
"???",
"????",
"Rang de port local",
"définit le délai par défaut d'une connexion TCP/IP default 60 -> 30",
"limitation du nombre de fichier ouvert",
"valeur max de PID",
"Interdire l'ajout de module kernel n'est plus possible de remttre à autoriser après...",
"Desactiver IPV6"
);
#smurf
#net.ipv4.icmp_echo_ignore_broadcasts = 1
# Turn on protection for bad icmp error messages
#net.ipv4.icmp_ignore_bogus_error_responses = 1
#net.ipv4.icmp_ignore_bogus_error_messages = 1
# Turn on syncookies for SYN flood attack protection
#net.ipv4.tcp_syncookies = 1
# Turn on and log spoofed, source routed, and redirect packets
#net.ipv4.conf.all.log_martians = 1
#net.ipv4.conf.default.log_martians = 1
# No source routed packets here
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv4.conf.default.accept_source_route = 0
# Turn on reverse path filtering
#net.ipv4.conf.all.rp_filter = 1
#net.ipv4.conf.default.rp_filter = 1
# Make sure no one can alter the routing tables
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv4.conf.default.accept_redirects = 0
#net.ipv4.conf.all.secure_redirects = 0
#net.ipv4.conf.default.secure_redirects = 0
# Don't act as a router
#net.ipv4.ip_forward = 0
#net.ipv4.conf.all.send_redirects = 0
#net.ipv4.conf.default.send_redirects = 0
# Tuen IPv6
#net.ipv6.conf.default.router_solicitations = 0
#net.ipv6.conf.default.accept_ra_rtr_pref = 0
#net.ipv6.conf.default.accept_ra_pinfo = 0
#net.ipv6.conf.default.accept_ra_defrtr = 0
#net.ipv6.conf.default.autoconf = 0
#net.ipv6.conf.default.dad_transmits = 0
#net.ipv6.conf.default.max_addresses = 1
# Optimization for port usefor LBs
# Increase system file descriptor limit
#fs.file-max = 65535
# Allow for more PIDs (to reduce rollover problems); may break some programs 32768
#kernel.pid_max = 65536
# Increase system IP port limits
#net.ipv4.ip_local_port_range = 2000 65000
# Increase TCP max buffer size setable using setsockopt()
#net.ipv4.tcp_rmem = 4096 87380 8388608
#net.ipv4.tcp_wmem = 4096 87380 8388608
# Increase Linux auto tuning TCP buffer limits
# min, default, and max number of bytes to use
# set max to at least 4MB, or higher if you use very high BDP paths
# Tcp Windows etc
#net.core.rmem_max = 8388608
#net.core.wmem_max = 8388608
#net.core.netdev_max_backlog = 5000
#kernel.modules_disabled = 1
#net.ipv6.conf.all.disable_ipv6=1 disable

for($i=0;$i<=$#list_sysctl;$i++){
  my $ret_sysctl=`if(sysctl $list_sysctl[$i] | grep -i "$list_sysctl[$i]\\s=\\s$list_sysctl_val[$i]");then echo "OK";else sysctl $list_sysctl[$i];fi`;
  if($ret_sysctl =~ /error:/i || $ret_sysctl =~ /OK/i ){
    next; #sysctl ok ou no exist
  }
  print $clear_string; #clearscreen
  print "Configuration Sysctl IPV4 & IPV6 + pid limit + fs limit open...\n";
  print "Paramètre systcl valeur actuel: $ret_sysctl\n";
  print "Paramètre systcl valeur proposé: $list_sysctl_val[$i]\n";
  print "Paramètre systcl description: $list_sysctl_desc[$i]\n";
  print "Voulez vous donner la valeur $list_sysctl_val[$i] au paramètre $list_sysctl[$i]? (Oui/Non) : ";
  my $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    $ras=`/sbin/sysctl -w "$list_sysctl[$i]=$list_sysctl_val[$i]"`;
    $ras=`if(grep -i "^\\s*$list_sysctl[$i]\\s*=" /etc/sysctl.conf);then sed -i.bak 's/^\\s*$list_sysctl[$i]\\s*=\\s*[0-9]*/$list_sysctl[$i]=$list_sysctl_val[$i]/g' /etc/sysctl.conf;else echo "$list_sysctl[$i]=$list_sysctl_val[$i]" >> /etc/sysctl.conf;fi`;
  }  
}

print "Disabling USB Mass Storage"
$ras=`echo "blacklist usb-storage" > /etc/modprobe.d/blacklist-usbstorage`;
#http://wiki.centos.org/HowTos/OS_Protection

#lister les modules charger
#lsmod -> modinfo -> pkg ?more 
#obtenir de l'information: provient de package?
#CONFIG_SECURITY_FILE_CAPABILITIES
#CONFIG_SECCOMP_FILTER a partir de 3.5
#/proc/sys/kernel/kptr_restrict
#dmesg_restrict = 1
#mmap_min_addr > 0
#créer un package kernel pour vmware classique: permet de ne plus avoir de modules inutiles et donc limiter les possibilités d'exploitation
#http://www.isalo.org/wiki.debian-fr/Compiler_et_patcher_son_noyau
#http://wiki.debian-facile.org/manuel:compiler_noyau
#http://www.tecmint.com/kernel-3-5-released-install-compile-in-redhat-centos-and-fedora/
#blockage l'import de nouveau modules
##########################################
#Verification des process & services lancé ------ Surface d'attaque
# trouver le packages concerné et affciher l'information
# afficher si process net IPV4 Et IPV6 ?
$listproc=`lsof -l | awk '{print \$1}' | sort -u`;
my @ar_listproc = split(/\n/g, $listproc);
$ras=`lsof -l | grep -iE "IPV4|IPV6"|awk '{print \$1}' |sort -u > /tmp/lsof-listip`;
#process appartient a un package?
print $clear_string; #clearscreen
print "Desirez vous ne voir que les processus lancés utilisant IPV4/IPv6? (Oui/Non) : ";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  $choix_net=1;
}
switch ($typeos) {
        case '1' { #debian ;
	  #process list appartenant ou non a un package
	  #lsof -l | grep -i "txt" | awk '{print $1" "$NF}' | sort -u |grep -i " /"|grep -iv " /proc/" > /tmp/lsof-list;awk '{print $2}' /tmp/lsof-list | awk -F "/" '{print "dpkg -S "$NF" 2>/dev/null|grep -i \""$0"$\""}'  | sh |sort -u > /tmp/lsof-list2; awk '{print "echo "$1" `grep -i \""$2"\" /tmp/lsof-list`" }' /tmp/lsof-list2  |sh | awk '{print "Package: "$1"== process "$2}'|sed 's/://g'|sort -u >/tmp/lsof-listx;awk '{print "echo Process "$1": `if(!(grep -i \""$2"$\" /tmp/lsof-list2));then echo \"ne fait pas partie de package\";fi`" }' /tmp/lsof-list |sh| grep -i "ne fait pas partie" >> /tmp/lsof-listx
	  $ras=`lsof -l | grep -i "txt" | awk '{print \$1" "\$NF}' | sort -u |grep -i " /"|grep -iv " /proc/" > /tmp/lsof-list;awk '{print \$2}' /tmp/lsof-list | awk -F "/" '{print "dpkg -S "\$NF" 2>/dev/null|grep -i \\\""\$0"\$\\\""}'  | sh |sort -u > /tmp/lsof-list2; awk '{print "echo "\$1" \`grep -i \\\""\$2"\\\" /tmp/lsof-list\`" }' /tmp/lsof-list2  |sh | awk '{print "Package: "\$1"== process "\$2}'|sed 's/://g'|sort -u >/tmp/lsof-listx;awk '{print "echo Process "\$1": \`if(!(grep -i \\\""\$2"\$\\\" /tmp/lsof-list2));then echo \\\"ne fait pas partie de package\\\";fi\`" }' /tmp/lsof-list |sh| grep -i "ne fait pas partie" >> /tmp/lsof-listx`;
	  #définir si le process a un lien avec un service dans /etc/init.d
	  #awk -F "==" '{print $1}' /tmp/lsof-listx 2>/dev/null|grep -i "^Package"|sed -e 's/^Package //g' | awk '{ print "echo \"Package "$1" `dpkg -L "$1" | grep -iE \"/rc\.d/|/init\.d/\" | tr \"\\n\" \" \"`\""}'|sh | grep -iE "/rc\.d/|/init\.d/" | sort -u > /tmp/proc_init
	  #$ras=`awk -F "==" '{print \$1}' /tmp/lsof-listx 2>/dev/null|grep -i "^Package"|sed -e 's/^Package //g' | awk '{ print "echo \\\"Package "\$1" \`dpkg -L "\$1" | grep -iE \\\"/rc\\.d/|/init\\.d/\\\" | tr \\\"\\\\n\\\" \\\" \\\"\`\\\""}'|sh | grep -iE "/rc\\.d/|/init\\.d/" | sort -u > /tmp/proc_init`;
	  #lien avec init.d hors packages
	  #awk -F ":" '{print $1}' /tmp/lsof-listx 2>/dev/null|grep -i "^Process"|sed -e 's/^Process //g'|awk '{print "grep -i \"^"$1"\" /tmp/lsof-list"}'|sh |awk '{print $2}'| awk -F "/" '{ print "echo \""$0" == `grep -i \"" $NF"\" /etc/init.d/*|sed -e \"s/\:.*$//g\" |sort -u`\""}' 2>/dev/null |sh |grep -i "init.d" >> /tmp/proc_init
	  #$ras=`awk -F ":" '{print \$1}' /tmp/lsof-listx 2>/dev/null|grep -i "^Process"|sed -e 's/^Process //g'|awk '{print "grep -i \\\"^"\$1"\\\" /tmp/lsof-list"}'|sh |awk '{print \$2}'| awk -F "/" '{ print "echo \\\""\$0" == `grep -i \\\"" \$NF"\\\" /etc/init.d/*|sed -e \\\"s/\\:.*\$//g\\\" |sort -u\`\\\""}' 2>/dev/null |sh |grep -i "init.d" >> /tmp/proc_init`;
	  #process evaluation securité ref: http://wiki.debian.org/Hardening
	  foreach $it_proc (@ar_listproc){
	    #install http://ftp.de.debian.org/debian/pool/main/h/hardening-wrapper/hardening-wrapper_1.29.tar.gz
	    $ras=`apt-get install hardening-includes -y`;
	    #lsof -l -c httpd | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\n\s/ -- /;bz'
	    #lsof -l -c httpd | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null||grep -iE "\syes$"|wc -l
	    #Val_A=`lsof -l -c httpd | grep -iE "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs file|grep -i "ELF"|wc -l `;Val_B=`lsof -l -c httpd | grep -iE "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\syes$"|wc -l`;echo $((Val_B/Val_A))
	    #lsof -l -c httpd | grep -i "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\n\s/ -- /;bz'
	    my $proc_vuln=`lsof -l -c $it_proc | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\\n\\s/ -- /;bz'`;
	    print $clear_string; #clearscreen
	    my $proc_net=`if(grep -i "^$it_proc\$" /tmp/lsof-listip 1>/dev/null);then echo "Oui" ;else echo "Non";fi`;
	    if($proc_net =~ /Oui/){
	      $note_net = -2;
	    } else {
	      $note_net = 2;
	    }
	    if($choix_net == 1 && $note_net == 2){
	      next;
	    }
	    $proc_net =~ s/\n//g;
	    print "Processus name: $it_proc\n";
	    print "Processus avec communication IPV4/V6: $proc_net\n";
	    my $proc_pkg=`if(grep -i "\\sprocess $it_proc\$" /tmp/lsof-listx 1>/dev/null);then echo au package \`grep -i "\\sprocess $it_proc" /tmp/lsof-listx|cut -d " " -f 2 |sed -e 's/==//g'\`;else echo "a aucun package.";fi`;
	    $proc_pkg =~ s/\n//g;
	    print "Processus est lié: $proc_pkg\n";
	    my $proc_init="";
	    $note_pkg = 0;
	    if($proc_pkg =~ /au package/){
	      $pkg_d_i=`grep -i "\\sprocess $it_proc" /tmp/lsof-listx|cut -d " " -f 2 |sed -e 's/==//g'`;
	      dpkg_info($pkg_d_i);
	      $note_pkg = 1;
	      $proc_init=`grep -i "process\\s$it_proc\$" /tmp/lsof-listx|awk -F "==" '{print \$1}'|grep -i "^Package"|sed -e 's/^Package //g' | awk '{ print "echo \\\"Package "\$1" \`dpkg -L "\$1" | grep -iE \\\"/rc\\.d/|/init\\.d/\\\" | tr \\\"\\\\n\\\" \\\" \\\"\`\\\""}'|sh | grep -iE "/rc\\.d/|/init\\.d/" | sort -u | cut -d " " -f 3`;
	    }
	    if(!($proc_init =~ /etc/)){
	      $proc_init=`grep -i "^$it_proc\\s" /tmp/lsof-list|awk '{print \$2}'| awk -F "/" '{ print "echo \\\""\$0" == \`grep -i \\\"" \$NF"\\\" /etc/init.d/*|sed -e \\\"s/\\:.*\$//g\\\" |sort -u\`\\\""}' 2>/dev/null |sh |grep -i "init.d" |cut -d " " -f 3`;
	    }
	    $proc_init =~ s/\n//g;
	    if($proc_init =~ /etc/){
	      print "Processus est lié au script init: $proc_init\n";
	      $note_init = 0;
	    } else {
	      $note_init = 1;
	    }
	    $note_proc=`lsof -l -c $it_proc | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\\syes\$"|wc -l`;
	    #TODO, faire un ldd de l'app pour voir si des libs non chargé
	    $note_lib=`Val_A=\`lsof -l -c $it_proc | grep -iE "mem" | awk '{for(i=1;i<=NF;i++) print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs file|grep -i "ELF"|wc -l \`;Val_B=\`lsof -l -c $it_proc | grep -iE "mem" | awk '{for(i=1;i<=NF;i++) print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\\syes\$"|wc -l\`;echo \$((Val_B/Val_A))`;
	    #afficher les libs -> $ras=`lsof -l -c $it_proc | grep -i "mem" | awk '{for(i=1;i<NF;i++) ;print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\\n\\s/ -- /;bz'`;
	    print "Processus code secure: $proc_vuln\n";
	    print "Processus secure note: $note_proc | Librairie dyn attachées au process note: $note_lib\n";
	    my $note_globale=$note_init+$note_lib+$note_net+$note_pkg+$note_proc;
	    print "Processus note globale: $note_globale\n";
	    if($min_risk > $note_globale ){
	      print "!!!! Ce processus peut comporter un risque pour votre securité !!!!\n";
	    #add }
	    }
	       my $input = "";
	      if($proc_pkg =~ /au package/){
		print "Voulez vous déinstaller le package? (oui/non)\n";
		 my $input = <STDIN>;
		 if ($input =~ /^yes/i | $input =~ /^oui/i){
		    if($proc_init =~ /etc/){
		      #stop init
		      $ras=`$proc_init stop`;
		    }else{
		      #kill proc
		      $ras=`killall -9 $it_proc`;
		    }
		    #remove pkg
		    my ($null1,$null2,$pkg_tmp_x)=split(/ /,$proc_pkg);
		    dpkg_remove($pkg_tmp_x);
		 }
	      }
	      if($proc_init =~ /etc/){
		print "Voulez vous stopper le init du processus? (oui/non) \n";
		my $input = <STDIN>;
		if ($input =~ /^yes/i | $input =~ /^oui/i){
		    #stop init
		    $ras=`$proc_init stop`;
		    #update-rc.d disable
		    my @tmp_split=split(/\//,$proc_init); 
		    $ras=`/usr/sbin/update-rc.d disable $tmp_split[$#tmp_split]`;
		} else {
		    my $proctomoa=`tomoyo-pstree |grep -E "\\s1.* $it_proc "`;
		    my $proctomop=`tomoyo-pstree |grep -E "\\s2.* $it_proc "`;
		    my $proctomor=`tomoyo-pstree |grep -E "\\s3.* $it_proc "`;
		    if($proctomoa=~/1/){
		      print "Processus en apprentissage par TOMOYO!! -> $proctomo\n";
		    } elsif($proctomop=~/2/){
		      print "Processus en mode permissif par TOMOYO!! -> $proctomo\n";
		    } elsif($proctomor=~/3/){
		      print "Processus en mode restrictif par TOMOYO!! -> $proctomo\n";
		    } else {
		      if($tomoyoacten==1 && $note_net == -2) {
			print "Voulez vous mettre le processus sous la protection de TOMOYO? (oui/non)\n";
			my $input = <STDIN>;
			if ($input =~ /^yes/i | $input =~ /^oui/i){
			  my $procschem=`lsof -c "$it_proc" |grep -i "REG"|grep -i "txt" | awk '{ print \$NF}'|sort -u`;
			  my @lprocch=split(/\n/,$procschem);
			  foreach $it_procch (@lprocch){
			    if($it_procch =~ /\//){
			      print "Initualisation domaine sur $it_procch\n";
			      $ras=`if(grep -i "^initialize_domain $it_procch from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain $it_procch from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
			    }
			  }
			  $ras=`if(grep -i "^initialize_domain $proc_init from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain $proc_init from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
			  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
			  $ras=`$proc_init restart`;
			  foreach $it_procch (@lprocch){
			    if($it_procch =~ /\//){
			      $ras=`tomoyo-setprofile 1 '<kernel> $it_procch'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
			    }
			  }
			  $ras=`$proc_init restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
			  $ras=`tomoyo-savepolicy`;
			  print "Tomoyo mise en place sur le processus en mode apprentissage...\n";
			}
		      }
		    }
		    if($cgroupsacten==1 && $note_net == -2) {
		      print "Voulez vous mettre des restrictions cgroup sur l'utilisateur lancant le processus  (oui/non)\n";
		      my $input = <STDIN>;
		      if ($input =~ /^yes/i | $input =~ /^oui/i){
			my $prouser=`lsof -c "$it_proc" | awk '{print \$3}' | grep -v "USER"|sort -u`;
			my @lprouser=split(/\n/,$prouser);
			foreach $it_prouser (@lprouser){
			  if($it_prouser =~ /root/){
			    print "Processus lancé avec utiliseur root... Veuillez lancer votre processus avec un autre utilisateur puis créer une règle cgroup!\n";
			  } else {
			    my $free=`free -m -t`;
			    print "Information sur votre ram et swap en MO:\n$free\n";
			    print "Veuillez indiquer la taille de memoire ram maximum pour l'utilisateur $it_prouser (rajouter M ou G a la fin si en MO ou GO): ";
			    my $memrl = <STDIN>;
			    $memrl =~ s/\n//g;
			    print "Veuillez indiquer la taille de memoire ram + swap maximum pour l'utilisateur $it_prouser (rajouter M ou G a la fin si en MO ou GO): ";
			    my $memrsl = <STDIN>;	
			    $memrsl =~ s/\n//g;
			    $cit_prouser=$it_prouser."_cgroups";
			    $ras=`if(grep "group $cit_prouser" /etc/cgconfig.conf);then echo CGROUPOK;else echo CGROUPKO;fi`;
			    if($ras=~/CGROUPOK/){
			      print "Le groupe $cit_prouser dans /etc/cgconfig.conf existe deja!";
			    } else {
			      $ras=`echo "group $cit_prouser {cpu{}cpuacct{}memory{memory.limit_in_bytes=$memrl;memory.memsw.limit_in_bytes=$memrsl;}devices{}}" >> /etc/cgconfig.conf`;
			      $ras=`echo "$it_prouser memory $cit_prouser" >> /etc/cgrules.conf`;
			      #restart deamon cg!!!!!!!!!!!!
			      $ras=`/etc/init.d/cgconfig restart;/etc/init.d/cgred restart`;
			    }  
			  }
			}
		      }
		    }
		    if($note_net == -2) {
		      print "Voulez vous mettre des regles IPTABLES sur le processus? (oui/non)\n";
		      my $input = <STDIN>;
		      if ($input =~ /^yes/i | $input =~ /^oui/i){
			$tcpro=`lsof -c "$it_proc"|grep -i "IPv4" |grep "UDP"|awk '{print \$NF}'|grep -v "localhost"|sort -u`;
			my @ltcpro=split(/\n/,$tcpro);
			foreach $it_tcpro (@ltcpro){
			    if($it_tcpro =~ /:/){
			      ($prhost,$prport)=split(/:/,$it_tcpro);
			      #trouver la correspondance host <=> interface
			      my $proip=`host $prhost | awk '{print \$NF}'`;
			      $proip =~ s/\n//g;
			      if ($proip eq "*"){
				print "Votre processus est lancé en ecoute sur toutes les interfaces pour le port $prport en protocole UDP (any).\n Vous devez reconfigurer votre service afin qu'il n'ecoute que l'interface utile.\n";
				print "Veuillez indiquez l'interface a utiliser (eth0 ,...):";
				my $int_temp = <STDIN>;
				$int_temp =~ s/\n//g;
				if($int_temp eq $interfacepriv){
				  $proip=$myippriv;
				} elsif($int_temp eq $INT_PUB){
				  $proip=$myippub;
				}
			      }
			      if($proip eq $myippriv){
				#$interfacepriv
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $interfacepriv en protocole UDP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PRIVCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PRIVCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $interfacepriv -p udp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } elsif ($proip eq $myippub){
				#$INT_PUB
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $INT_PUB en protocole UDP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PUBCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PUBCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $INT_PUB -p udp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } 
			    }
			}
			#tcp inspection processus
			$tcpro=`lsof -c "$it_proc" | grep -i "IPv4" |grep "LISTEN" | grep "TCP"| awk '{print \$(NF-1)}'|grep -v "localhost"|sort -u`;
			my @ltcpro=split(/\n/,$tcpro);
			foreach $it_tcpro (@ltcpro){
			    if($it_tcpro =~ /:/){
			      ($prhost,$prport)=split(/:/,$it_tcpro);
			      #trouver la correspondance host <=> interface
			      my $proip=`host $prhost | awk '{print \$NF}'`;
			      $proip =~ s/\n//g;
			      if ($proip eq "*"){
				print "Votre processus est lancé en ecoute sur toutes les interfaces pour le port $prport en protocole TCP (any).\n Vous devez reconfigurer votre service afin qu'il n'ecoute que l'interface utile.\n";
				print "Veuillez indiquez l'interface a utiliser (eth0 ,...):";
				my $int_temp = <STDIN>;
				$int_temp =~ s/\n//g;
				if($int_temp eq $interfacepriv){
				  $proip=$myippriv;
				} elsif($int_temp eq $INT_PUB){
				  $proip=$myippub;
				}
			      }
			      if($proip eq $myippriv){
				#$interfacepriv
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $interfacepriv en protocole TCP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PRIVCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PRIVCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $interfacepriv -p tcp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } elsif ($proip eq $myippub){
				#$INT_PUB
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $INT_PUB en protocole TCP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PUBCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PUBCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $INT_PUB -p tcp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } 
			    }
			}
		      }
		    }
		    if($note_net == -2) {
		      print "Voulez vous autoriser le processus sur le tcp wrapper /etc/hosts.allow? (oui/non) [http://www.centos.org/docs/4/html/rhel-rg-en-4/s1-tcpwrappers-access.html]\n";
		      $input = <STDIN>;
		      if ($input =~ /^yes/i | $input =~ /^oui/i){
			print "Veuillez entrer la ligne a rajouter dans /etc/hosts.allow (voir ref. pour syntax - verifier la bonne syntaxe du fichier par la commande: tcpchk):\n";
			my $hostallow = <STDIN>;
			$ras=`if(grep -e "$hostallow" /etc/hosts.allow);then echo OK;else echo "$hostallow" >> /etc/hosts.allow;fi`;	
		      }
		    }
		}
	      }
	      print "Processus suivant... (appuyer sur une touche)\n";
	      my $input = <STDIN>;
	    #}
	  }
	}
	case '2' { #centos ;
	  #install http://ftp.fr.debian.org/debian/pool/main/h/hardening-wrapper/hardening-includes_1.29_all.deb
	  $ras=`if(rpm -qa wget |wc -l|grep -iv "^0\$");then wget http://ftp.fr.debian.org/debian/pool/main/h/hardening-wrapper/hardening-includes_1.29_all.deb -O /tmp/hardening.deb;cd /tmp;ar vx /tmp/hardening.deb data.tar.gz;tar -xzvf /tmp/data.tar.gz ./usr/bin/hardening-check;cp -f /tmp/usr/bin/hardening-check /usr/bin/hardening-check;else yum install -y wget; wget http://ftp.fr.debian.org/debian/pool/main/h/hardening-wrapper/hardening-includes_1.29_all.deb -O /tmp/hardening.deb;cd /tmp; ar vx /tmp/hardening.deb data.tar.gz;tar -xzvf /tmp/data.tar.gz ./usr/bin/hardening-check;cp -f /tmp/usr/bin/hardening-check /usr/bin/hardening-check ;yum remove -y wget;fi`;
	  #process list appartenant a un package ou non
	  #lsof -l | grep -i "txt" | awk '{print $1" "$NF}' | uniq |grep -i " /"|grep -iv " /proc/" | awk '{print "echo \"Process "$1" == \`rpm -qf "$2"\`\""}' 2> /dev/null | sh | sort -u > /tmp/lsof-list
	  $ras=`lsof -l | grep -i "txt" | awk '{print \$1" "\$NF}' | uniq |grep -i " /"|grep -iv " /proc/" | awk '{print "echo \\\"Process "\$1" == \\\`rpm -qf "\$2"\\\`\\\""}' 2> /dev/null | sh | sort -u > /tmp/lsof-list`;
	  #définir si le process a un lien avec un service dans /etc/init.d
	  #sed -e 's/\s*//g' /tmp/lsof-list |grep -iv "appartientàaucunpaquetage" |awk -F '=='  '{print "echo Package "$2" `rpm -ql "$2" | grep -iE \"/rc\.d/|/init\.d/\"`"}' 2>/dev/null | sh | grep -iE "/rc\.d/|/init\.d/" | sort -u > /tmp/proc_init
	  #$ras=`sed -e 's/\\s*//g' /tmp/lsof-list |grep -iv "appartientàaucunpaquetage" |awk -F '=='  '{print "echo Package "\$2" \`rpm -ql "\$2" | grep -iE \\\"/rc\\.d/|/init\\.d/\\\"\`"}' 2>/dev/null | sh | grep -iE "/rc\\.d/|/init\\.d/" | sort -u > /tmp/proc_init`;
	  #lien avec init.d hors packages
	  #grep -i "n'appartient" /tmp/lsof-list | awk '{ print $6}' | awk -F "/" '{ print "echo \""$0" == `grep -i \"" $NF"\" /etc/init.d/*|sed -e \"s/\:.*$//g\" |sort -u`\""}' 2>/dev/null |sh |grep -i "init.d" >> /tmp/proc_init
	  #$ras=`grep -i "n'appartient" /tmp/lsof-list | awk '{ print \$6}' | awk -F "/" '{ print "echo \\\""\$0" == \`grep -i \\\"" \$NF"\\\" /etc/init.d/*|sed -e \\\"s/\\:.*\$//g\\\" |sort -u\`\\\""}' 2>/dev/null |sh |grep -i "init.d" >> /tmp/proc_init`;
	  #process evaluation securité ref: http://wiki.debian.org/Hardening
	  foreach $it_proc (@ar_listproc){
	    #install http://ftp.de.debian.org/debian/pool/main/h/hardening-wrapper/hardening-wrapper_1.29.tar.gz
	    #$ras=`apt-get install hardening-includes -y`;
	    #lsof -l -c httpd | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\n\s/ -- /;bz'
	    #lsof -l -c httpd | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\syes$"|wc -l
	    #Val_A=`lsof -l -c httpd | grep -iE "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs file|grep -i "ELF"|wc -l `;Val_B=`lsof -l -c httpd | grep -iE "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\syes$"|wc -l`;echo $((Val_B/Val_A))
	    #lsof -l -c httpd | grep -i "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\n\s/ -- /;bz'
	    my $proc_vuln=`lsof -l -c $it_proc | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\\n\\s/ -- /;bz'`;
	    print $clear_string; #clearscreen
	    my $proc_net=`if(grep -i "^$it_proc\$" /tmp/lsof-listip 1>/dev/null);then echo "Oui" ;else echo "Non";fi`;
	    if($proc_net =~ /Oui/){
	      $note_net = -2;
	    } else {
	      $note_net = 2;
	    }
	    if($choix_net == 1 && $note_net == 2){
	      next;
	    }
	    $proc_net =~ s/\n//g;
	    print "Processus name: $it_proc\n";
	    print "Processus avec communication IPV4/V6: $proc_net\n";
	    my $proc_pkg=`if(grep -i "^Process $it_proc\\s" /tmp/lsof-list|cut -d " " -f 4 |grep -iv "^le\$" 1>/dev/null);then echo au package \`grep -i "^Process $it_proc\\s" /tmp/lsof-list|cut -d " " -f 4 |grep -iv "^le\$"\`;else echo "a aucun package.";fi`;
	    $proc_pkg =~ s/\n//g;
	    print "Processus est lié: $proc_pkg\n";
	    my $proc_init="";
	    if($proc_pkg =~ /au package/){
	      $pkg_d_i=`grep -i "^Process $it_proc\\s" /tmp/lsof-list|cut -d " " -f 4 |grep -iv "^le\$"`;
	      rpm_info($pkg_d_i);
	      $note_pkg = 1;
	      $proc_init=`grep -i "Process\\s$it_proc\\s" /tmp/lsof-list |awk -F '=='  '{print "echo Package "\$2" \`rpm -ql "\$2" | grep -iE \\\"/rc\\.d/|/init\\.d/\\\"\`"}' 2>/dev/null | sh | grep -iE "/rc\\.d/|/init\\.d/" | sort -u | cut -d " " -f 3`;
	    }else{
	      $note_pkg = 0;
	      $proc_init=`grep -i "Process\\s$it_proc\\s" /tmp/lsof-list | awk '{ print \$6}' | awk -F "/" '{ print "echo \\\""\$0" == \`grep -i \\\"" \$NF"\\\" /etc/init.d/*|sed -e \\\"s/\\:.*\$//g\\\" |sort -u\`\\\""}' 2>/dev/null |sh |grep -i "init.d" |cut -d " " -f 3|sort -u|tr "\\n" " "`;
	    }
	    $proc_init =~ s/\n//g;
	    if($proc_init =~ /etc/){
	      print "Processus est lié au script init: $proc_init\n";
	      $note_init = 0;
	    } else {
	      $note_init = 1;
	    }
	    $note_proc=`lsof -l -c $it_proc | grep -i "txt" | awk '{for(i=1;i<NF;i++) ;print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\\syes\$"|wc -l`;
	    #TODO, faire un ldd de l'app pour voir si des libs non chargé
	    $note_lib=`Val_A=\`lsof -l -c $it_proc | grep -iE "mem" | awk '{for(i=1;i<=NF;i++) print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs file|grep -i "ELF"|wc -l \`;Val_B=\`lsof -l -c $it_proc | grep -iE "mem" | awk '{for(i=1;i<=NF;i++) print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|grep -iE "\\syes\$"|wc -l\`;echo \$((Val_B/Val_A))`;
	    #afficher les libs -> $ras=`lsof -l -c $it_proc | grep -i "mem" | awk '{for(i=1;i<NF;i++) ;print \$i}'|grep -iE "^/.*/.*"|sort -u|xargs /usr/bin/hardening-check 2>/dev/null|sed -e ':z;N;s/\\n\\s/ -- /;bz'`;
	    print "Processus code secure: $proc_vuln\n";
	    print "Processus secure note: $note_proc | Librairie dyn attachées au process note: $note_lib\n";
	    my $note_globale=$note_init+$note_lib+$note_net+$note_pkg+$note_proc;
	    print "Processus note globale: $note_globale\n";
	     if($min_risk > $note_globale ){
	      print "!!!! Ce processus peut comporter un risque pour votre securité !!!!\n";
	     #add }
	     }
	       my $input = "";
	      if($proc_pkg =~ /au package/){
		print "Voulez vous déinstaller le package? (oui/non)\n";
		 my $input = <STDIN>;
		 if ($input =~ /^yes/i | $input =~ /^oui/i){
		    if($proc_init =~ /etc/){
		      #stop init
		      $ras=`$proc_init stop`;
		    }else{
		      #kill proc
		      $ras=`killall -9 $it_proc`;
		    }
		    #remove pkg
		    my ($null1,$null2,$pkg_tmp_x)=split(/ /,$proc_pkg);
		    rpm_remove($pkg_tmp_x);
		 }
	      }
	      if($proc_init =~ /etc/){
		print "Voulez vous stopper le init du processus? (oui/non)\n";
		my $input = <STDIN>;
		if ($input =~ /^yes/i | $input =~ /^oui/i){
		    #stop init
		    $ras=`$proc_init stop`;
		    #chkconfig --del
		    my @tmp_split=split(/\//,$proc_init); 
		    $ras=`/sbin/chkconfig --del $tmp_split[$#tmp_split]`;
		} else {
		    my $proctomoa=`tomoyo-pstree |grep -E "\\s1.* $it_proc "`;
		    my $proctomop=`tomoyo-pstree |grep -E "\\s2.* $it_proc "`;
		    my $proctomor=`tomoyo-pstree |grep -E "\\s3.* $it_proc "`;
		    if($proctomoa=~/1/){
		      print "Processus en apprentissage par TOMOYO!! -> $proctomo\n";
		    } elsif($proctomop=~/2/){
		      print "Processus en mode permissif par TOMOYO!! -> $proctomo\n";
		    } elsif($proctomor=~/3/){
		      print "Processus en mode restrictif par TOMOYO!! -> $proctomo\n";
		    } else {
		      if($tomoyoacten==1 && $note_net == -2) {
			print "Voulez vous mettre le processus sous la protection de TOMOYO? (oui/non)\n";
			my $input = <STDIN>;
			if ($input =~ /^yes/i | $input =~ /^oui/i){
			  my $procschem=`lsof -c "$it_proc" |grep -i "REG"|grep -i "txt" | awk '{ print \$NF}'|sort -u`;
			  my @lprocch=split(/\n/,$procschem);
			  foreach $it_procch (@lprocch){
			    if($it_procch =~ /\//){
			      $ras=`if(grep -i "^initialize_domain $it_procch from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain $it_procch from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
			    }
			  }
			  $ras=`if(grep -i "^initialize_domain $proc_init from any\$" /etc/tomoyo/policy/current/exception_policy.conf);then echo ok;else echo "initialize_domain $proc_init from any" >>  /etc/tomoyo/policy/current/exception_policy.conf;fi`;
			  $ras=`cat /etc/tomoyo/policy/current/exception_policy.conf | tomoyo-loadpolicy -ef`; # import les nouveaux domaines
			  $ras=`$proc_init restart`;
			  foreach $it_procch (@lprocch){
			    if($it_procch =~ /\//){
			      $ras=`tomoyo-setprofile 1 '<kernel> $it_procch'`; # tomoyo mode apprentissage - pour verifier si bien en apprentissage tomoyo-pstree|grep ntpd: doit etre marqué 1
			    }
			  }
			  $ras=`$proc_init restart`; # permet d'inscrire les elements de demarage dans tomoyo apprentissage
			  $ras=`tomoyo-savepolicy`;
			  print "Tomoyo mise en place sur le processus en mode apprentissage...\n";
			}
		      }
		    }
		    if($cgroupsacten==1 && $note_net == -2) {
		      print "Voulez vous mettre des restrictions cgroup sur l'utilisateur lancant le processus  (oui/non)\n";
		      my $input = <STDIN>;
		      if ($input =~ /^yes/i | $input =~ /^oui/i){
			my $prouser=`lsof -c "$it_proc" | awk '{print \$3}' | grep -v "USER"|sort -u`;
			my @lprouser=split(/\n/,$prouser);
			foreach $it_prouser (@lprouser){
			  if($it_prouser =~ /root/){
			    print "Processus lancé avec utiliseur root... Veuillez lancer votre processus avec un autre utilisateur puis créer une règle cgroup!\n";
			  } else {
			    my $free=`free -m -t`;
			    print "Information sur votre ram et swap en MO:\n$free\n";
			    print "Veuillez indiquer la taille de memoire ram maximum pour l'utilisateur $it_prouser (rajouter M ou G a la fin si en MO ou GO): ";
			    my $memrl = <STDIN>;
			    $memrl =~ s/\n//g;
			    print "Veuillez indiquer la taille de memoire ram + swap maximum pour l'utilisateur $it_prouser (rajouter M ou G a la fin si en MO ou GO): ";
			    my $memrsl = <STDIN>;	
			    $memrsl =~ s/\n//g;
			    $cit_prouser=$it_prouser."_cgroups";
			    $ras=`if(grep "group $cit_prouser" /etc/cgconfig.conf);then echo CGROUPOK;else echo CGROUPKO;fi`;
			    if($ras=~/CGROUPOK/){
			      print "Le groupe $cit_prouser dans /etc/cgconfig.conf existe deja!";
			    } else {
			      $ras=`echo "group $cit_prouser { cpu {} cpuacct {} memory { memory.limit_in_bytes=$memrl; memory.memsw.limit_in_bytes=$memrsl;} devices {} }" >> /etc/cgconfig.conf`;
			      $ras=`echo "$it_prouser memory $cit_prouser" >> /etc/cgrules.conf`;
			      #restart deamon cg!!!!!!!!!!!!
			      $ras=`/etc/init.d/cgconfig restart;/etc/init.d/cgred restart`;
			    }  
			  }
			}
		      }
		    }
		    if($note_net == -2) {
		      print "Voulez vous mettre des regles IPTABLES sur le processus? (oui/non)\n";
		      my $input = <STDIN>;
		      if ($input =~ /^yes/i | $input =~ /^oui/i){
			$tcpro=`lsof -c "$it_proc"|grep -i "IPv4" |grep "UDP"|awk '{print \$NF}'|grep -v "localhost"|sort -u`;
			my @ltcpro=split(/\n/,$tcpro);
			foreach $it_tcpro (@ltcpro){
			    if($it_tcpro =~ /:/){
			      ($prhost,$prport)=split(/:/,$it_tcpro);
			      #trouver la correspondance host <=> interface
			      my $proip=`host $prhost | awk '{print \$NF}'`;
			      $proip =~ s/\n//g;
			      if ($proip eq "*"){
				print "Votre processus est lancé en ecoute sur toutes les interfaces pour le port $prport en protocole UDP (any).\n Vous devez reconfigurer votre service afin qu'il n'ecoute que l'interface utile.\n";
				print "Veuillez indiquez l'interface a utiliser (eth0 ,...):";
				my $int_temp = <STDIN>;
				$int_temp =~ s/\n//g;
				if($int_temp eq $interfacepriv){
				  $proip=$myippriv;
				} elsif($int_temp eq $INT_PUB){
				  $proip=$myippub;
				}
			      }
			      if($proip eq $myippriv){
				#$interfacepriv
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $interfacepriv en protocole UDP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $interfacepriv -p udp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PRIVCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PRIVCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $interfacepriv -p udp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } elsif ($proip eq $myippub){
				#$INT_PUB
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $INT_PUB en protocole UDP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $INT_PUB -p udp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PUBCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PUBCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $INT_PUB -p udp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } 
			    }
			}
			#tcp inspection processus
			$tcpro=`lsof -c "$it_proc" | grep -i "IPv4" |grep "LISTEN" | grep "TCP"| awk '{print \$(NF-1)}'|grep -v "localhost"|sort -u`;
			my @ltcpro=split(/\n/,$tcpro);
			foreach $it_tcpro (@ltcpro){
			    if($it_tcpro =~ /:/){
			      ($prhost,$prport)=split(/:/,$it_tcpro);
			      #trouver la correspondance host <=> interface
			      my $proip=`host $prhost | awk '{print \$NF}'`;
			      $proip =~ s/\n//g;
			      if ($proip eq "*"){
				print "Votre processus est lancé en ecoute sur toutes les interfaces pour le port $prport en protocole TCP (any).\n Vous devez reconfigurer votre service afin qu'il n'ecoute que l'interface utile.\n";
				print "Veuillez indiquez l'interface a utiliser (eth0 ,...):";
				my $int_temp = <STDIN>;
				$int_temp =~ s/\n//g;
				if($int_temp eq $interfacepriv){
				  $proip=$myippriv;
				} elsif($int_temp eq $INT_PUB){
				  $proip=$myippub;
				}
			      }
			      if($proip eq $myippriv){
				#$interfacepriv
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $interfacepriv en protocole TCP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $interfacepriv -p tcp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PRIVCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PRIVCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $interfacepriv -p tcp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } elsif ($proip eq $myippub){
				#$INT_PUB
				print "Creation d'une regle iptables pour accepter les flux sur l'interface $INT_PUB en protocole TCP vers le port $prport.\n";
				print "Voulez vous rajouter une règles de filtrage plus restrictif sur l'adresse IP source? (oui/non)";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				    print "Veuillez entrer l'adressage";
				    $srcip = <STDIN>;
				    $srcip =~ s/\n//g;
				    print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -s $srcip -j ACCEPT";
				    $ras=`iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -s $srcip -j ACCEPT`;
				}else{
				  print "INSERT: iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -j ACCEPT";
				  $ras=`iptables -t filter -I INPUT -i $INT_PUB -p tcp --dport $prport -j ACCEPT`;
				}
				print "Voulez vous mettre des regles QOS (TC) sur le processus?  (oui/non)\n";
				my $input = <STDIN>;
				if ($input =~ /^yes/i | $input =~ /^oui/i){
				  print "Veuillez entrer la classe (entre 1 et $PUBCLASS):";
				  my $prclass = <STDIN>;
				  $prclass =~ s/\n//g;
				  if($prclass<1 && $prclass >= $PUBCLASS){
				      $prclass=100;
				  } else {
				      $prclass=$prclass."0";
				  }
				  $ras=`iptables -t mangle -A OUTPUT -o $INT_PUB -p tcp --sport $prport -j MARK --set-mark $prclass`;
				}
			      } 
			    }
			}
		      }
		    }
		    if($note_net == -2) {
		      print "Voulez vous autoriser le processus sur le tcp wrapper /etc/hosts.allow? (oui/non) [http://www.centos.org/docs/4/html/rhel-rg-en-4/s1-tcpwrappers-access.html]\n";
		      $input = <STDIN>;
		      if ($input =~ /^yes/i | $input =~ /^oui/i){
			print "Veuillez entrer la ligne a rajouter dans /etc/hosts.allow (voir ref. pour syntax - verifier la bonne syntaxe du fichier par la commande: tcpchk):\n";
			my $hostallow = <STDIN>;
			$ras=`if(grep -e "$hostallow" /etc/hosts.allow);then echo OK;else echo "$hostallow" >> /etc/hosts.allow;fi`;	
		      }
		    }
		}
	      }
	      print "Processus suivant... (appuyer sur une touche)\n";
	      my $input = <STDIN>;
	    #}
	  }
	}
}
#note sur 5 pour lib (moyenne)
#affichage#note
#(lsof -l -c httpd | grep -iE "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs file|grep -i "ELF"|wc -l > /tmp/nb_total_lib
#lsof -l -c httpd | grep -iE "mem" | awk '{for(i=1;i<NF;i++) ;print $i}'|grep -iE "^/.*/.*"|sort -u|xargs /root/hardening-check 2>/dev/null|grep -iE "\syes$"|wc -l > /tmp/nb_total_yes
# afficher le risque rapport package [base ou apres install ou hors package] & net & compilation d'option
#Est ce que le process ou services lancé vous est utile?
# lister les dependances et fichier utilisé si present dans package sinon afficher
print $clear_string; #clearscreen
my $netstat =`netstat -anp --inet | grep LISTEN | grep -v 127.0.0.1:`;
print "PORT LISTEN on 0.0.0.0:\n$netstat\n";
print "Verification des services installés lancés et non lancés...(appuyer sur une touche pour continuer)\n";
my $input = <STDIN>;
switch ($typeos){
        case '1' { #debian
	  # tasksel --list-tasks
	  $ras = `/usr/bin/apt-get update;/usr/bin/apt-get install -y rcconf apt-file;apt-file update`;
	  if ($DEBUG==1){ print "$ras";}
	  $services_on=`/usr/sbin/rcconf --list |grep -i "\\son\$"|cut -d " " -f 1|tr "\\n" " "`;
	  my @servtmp=split(/ /,$services_on);
	  foreach $it_ser (@servtmp){
	    #si pkg info et demande déinstall?
	    my $qpkg="";
	    $qpkg=`apt-file search "/etc/init.d/$it_ser"|grep -i "/etc/init.d/$it_ser\$"|cut -d ":" -f 1`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser est lancé par default au démarrage du systeme.\n Il appartient au package:\n";
	      dpkg_info($qpkg);
	      print "Voulez vous stopper le service $it_ser definitivement? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		$ras=`update-rc.d stop $it_ser`;
	      }
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 dpkg_remove($qpkg);
	      }
	      #si service reconnu dans la base conseil
	      switch ($it_ser){
		case 'httpd' {
		#conseil config secure
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service:";
		  print " ->Fichier: /etc/httpd/";
		  print "  -->";
		  my $input = <STDIN>;
		}
		case 'apache2' {
		#conseil config secure
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  #information
		  print "-> Limiter l'information donnée par le web:";
		  print " -> Limiter l'information donnée par apache & module:";
		  print " -> Limiter l'information donnée par php:";
		  print " -> Eviter le scan de pages web type spiderman";
		  print " -> Trop de reuqetes en erreurs sur la meme ip (fail2ban)";
		  print " -> Mettre en place un reverse-proxy -> limite l'information header renvoyé";
		  print "-> Restreindre la surface d'exploitation:";
		  print " -> Limiter les interfaces/adresses d'ecoutes au strict nécéssaire:";
		  print " -> Limiter les ports d'ecoutes au strict nécéssaire:";
		  print " -> Limiter l'accès aux données par htacces";
		  print " -> Limiter l'accès aux users agent connu";
		  print " -> Limiter les methodes (GET, POST)";
		  print " -> Limiter l'acces au données en lecture/ecriture/exec -> montage partition/droit user-grp";
		  print " -> Desactiver tous les modules non utilisé avec a2dismod, modules activés:\n";
		  my $modload=`ls -l /etc/apache2/mods-enabled/*.load|awk '{print \$NF}'|awk -F "/" '{print \$NF}'|sed -e 's/\\.load//g'| sed -e ':z;N;s/\\n/ /;bz'`;
		  print "  --> $modload";
		  print " -> Limiter les fonctions et la memoire utilisé par php";
		  print " -> Mettre un module de limitation de debit/requetes -> mod_evasive";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print " -> Mettre en place un reverse-proxy";
		  print " -> Mettre un WAF -> mod_security";
		  print " -> Mettre un WAF SQL -> sqlgreen";
		  print " -> analyse de la coherence du chemin & analyse frequencielle";
		  print "-> Recuperer de l'informations utiles:";
		  print " -> Costume log";
		  print "-> Verification du code executé:";
		  print " -> Controler vos sites avec pixy (Analyse TAINT)";

		  print " -> Fichier: /etc/apache2/";
		  print "  -->";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'bind9' {
		  #http://www.zonecheck.fr/download.shtml
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée par le dns:";
		  print " -> Limiter l'information du service meme";
		  print " -> Limiter l'information donnée par le service";
		  print "  --> champs txt";
		  print "  --> query";
		  print "  --> update";
		  print "  --> transfer";
		  print "  --> view";
		  print " -> Limiter le scan de classe (ATTENTION SPOOFING UDP)";
		  print "-> Restreindre la surface d'exploitation:";
		  print " -> Limiter les interfaces/adresses d'ecoutes au strict nécéssaire:";
		  print " -> Limiter les ports d'ecoutes au strict nécéssaire:";
		  print " -> Limiter les requetes: rate";
		  print " -> L'exploitation de faille memoire est limité par la compilation HARDENING";
		  print " -> Limiter les requetes: rate";
		  print " -> Limiter les risques de tunnel (si proxy web) -> view?";
		  print " -> Cache poisonning: nombreuses requetes, ID & SPORT randomize, DNSSEC -> dnssec-validation yes;";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'named' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'dhcpd' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print " -> DHCP snooping";
		  print " -> limiter l'attribution d'IP";
		  print " -> ";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'postfix' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'mysql' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'ldap' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'dovecot' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case 'imapd' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
		case '' {
		  print "Vous trouverez ci-dessous les éléments important a configurer pour ce service.\n";
		  print "-> Limiter l'information donnée:";
		  print "-> Restreindre la surface d'exploitation:";
		  print "-> Verification des normes protocolaires et de syntaxe/sementics des requetes:";
		  print "-> Recuperer de l'informations utiles:";
		  print "Appuyer sur une touche pour continuer...\n";
		  my $input = <STDIN>;
		}
	      }
	    } else {
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser est lancé par default au démarrage du systeme.\n";
	      my $desci=`grep -i "^DESC=" /etc/init.d/$it_ser|sed -e 's/^DESC=//g'|sed -e 's/"//g'`;
	      print "Description du service (si indiqué): $desci.\n";
	      print "Voulez vous stopper le service $it_ser definitivement? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		$ras=`update-rc.d stop $it_ser`;
	      }
	    }
	    print "Service suivant... (Appuyer sur une touche)\n";
	    my $input = <STDIN>;
	  }
	  my @servtmp=split(/ /,$services_off);
	  $services_off=`/usr/sbin/rcconf --list |grep -i "\\soff\$"|cut -d " " -f 1|tr "\\n" " "`;
	  foreach $it_ser (@servtmp){
	    #si pkg info et demande déinstall?
	    my $qpkg="";
	    $qpkg=`apt-file search "/etc/init.d/$it_ser"|grep -i "/etc/init.d/$it_ser\$"|cut -d ":" -f 1`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser n est pas lancé par default au démarrage du systeme.\n Il appartient au package:\n";
	      dpkg_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 dpkg_remove($qpkg);
	      }
	    } else {
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser n est pas lancé par default au démarrage du systeme.\n";
	      my $desci=`grep -i "^DESC=" /etc/init.d/$it_ser|sed -e 's/^DESC=//g'|sed -e 's/"//g'`;
	      print "Description du service (si indiqué): $desci.\n";
	    }
	    print "Service suivant... (Appuyer sur une touche)\n";
	    my $input = <STDIN>;
	  }
	}
        case '2' { #centos
	  $services_on=`/sbin/chkconfig --list | grep -i "marche" | awk '{print \$1}' | tr "\\n" " "`;
	   my @servtmp=split(/ /,$services_on);
	  foreach $it_ser (@servtmp){
	    #si pkg info et demande déinstall?
	    my $qpkg="";
	    $qpkg=`rpm -qf "/etc/init.d/$it_ser"`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser est lancé par default au démarrage du systeme.\n Il appartient au package:\n";
	      rpm_info($qpkg);
	      print "Voulez vous stopper le service $it_ser definitivement? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		$ras=`chkconfig --del $it_ser`;
	      }
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 rpm_remove($qpkg);
	      }
	    } else {
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser est lancé par default au démarrage du systeme.\n";
	      my $desci=`grep -i "^DESC=" /etc/init.d/$it_ser|sed -e 's/^DESC=//g'|sed -e 's/"//g'`;
	      print "Description du service (si indiqué): $desci.\n";
	      print "Voulez vous stopper le service $it_ser definitivement? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		$ras=`chkconfig --del $it_ser`;
	      }
	    }
	    print "Service suivant... (Appuyer sur une touche)\n";
	    my $input = <STDIN>;
	  }
	  my @servtmp=split(/ /,$services_off);
	  $services_off=`/sbin/chkconfig --list |grep -i "5:arrêt"| awk '{print \$1}' | tr "\\n" " "`;
	  foreach $it_ser (@servtmp){
	    #si pkg info et demande déinstall?
	    my $qpkg="";
	    $qpkg=`rpm -qf "/etc/init.d/$it_ser"`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser n est pas lancé par default au démarrage du systeme.\n Il appartient au package:\n";
	      rpm_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 rpm_remove($qpkg);
	      }
	    } else {
	      print $clear_string; #clearscreen
	      print "Le service: $it_ser n est pas lancé par default au démarrage du systeme.\n";
	      my $desci=`grep -i "^DESC=" /etc/init.d/$it_ser|sed -e 's/^DESC=//g'|sed -e 's/"//g'`;
	      print "Description du service (si indiqué): $desci.\n";
	    }
	    print "Service suivant... (Appuyer sur une touche)\n";
	    my $input = <STDIN>;
	  }
	}
}
print "OK\n";
##########################################
#surface d'attaque SUID/SGID
$sgid=`find / -type f -perm -02000 -ls 2>/dev/null|awk '{print \$NF}'`;
@lsgid=split(/\n/,$sgid);
foreach $it_ser (@lsgid){
  switch ($typeos){
        case '1' { #debian
	  my $qpkg="";
	    $qpkg=`apt-file search "$it_ser"|grep -i "$it_ser\$"|cut -d ":" -f 1`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "L'executable SGID: $it_ser appartient au package:\n";
	      dpkg_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 dpkg_remove($qpkg);
	      }
	    }else{
	      print "L'executable SGID: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Executable SGID suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
	case '2' { #centos
	  my $qpkg="";
	    $qpkg=`rpm -qf "$it_ser"`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "L'executable SGID: $it_ser appartient au package:\n";
	      rpm_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 rpm_remove($qpkg);
	      }
	}else{
	      print "L'executable SGID: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Executable SGID suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
  }
}
$suid=`find / -type f -perm -04000 -ls 2>/dev/null|awk '{print \$NF}'`;
@lsuid=split(/\n/,$suid);
foreach $it_ser (@lsuid){
  switch ($typeos){
        case '1' { #debian
	  my $qpkg="";
	    $qpkg=`apt-file search "$it_ser"|grep -i "$it_ser\$"|cut -d ":" -f 1`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "L'executable SUID: $it_ser appartient au package:\n";
	      dpkg_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 dpkg_remove($qpkg);
	      }
	    }else{
	      print "L'executable SUID: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Executable SUID suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
	case '2' { #centos
	  my $qpkg="";
	    $qpkg=`rpm -qf "$it_ser"`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "L'executable SUID: $it_ser appartient au package:\n";
	      rpm_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 rpm_remove($qpkg);
	      }
	}else{
	      print "L'executable SUID: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Executable SUID suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
  }
}
$file_sp=`find / \\( -nouser -o -nogroup \\) 2>/dev/null|awk '{print \$NF}'`; # fichier sans prorietaire
@lfile_sp=split(/\n/,$file_sp);
foreach $it_ser (@lfile_sp){
  switch ($typeos){
        case '1' { #debian
	  my $qpkg="";
	    $qpkg=`apt-file search "$it_ser"|grep -i "$it_ser\$"|cut -d ":" -f 1`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le fichier sans propritaire: $it_ser appartient au package:\n";
	      dpkg_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 dpkg_remove($qpkg);
	      }
	    }else{
	      print "Le fichier sans propritaire: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Fichier sans propritaire suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
	case '2' { #centos
	  my $qpkg="";
	    $qpkg=`rpm -qf "$it_ser"`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le fichier sans propritaire: $it_ser appartient au package:\n";
	      rpm_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 rpm_remove($qpkg);
	      }
	}else{
	      print "Le fichier sans propritaire: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Fichier sans propritaire suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
  }
}
$file_sw=`find / -perm -2 ! -type l -ls 2>/dev/null|awk '{print \$NF}'|grep -v "^/proc/"|grep -v "^/dev/|grep -v "^/cgroup/""`; # fichier système avec droit en ecriture
@lfile_sw=split(/\n/,$file_sw);
foreach $it_ser (@lfile_sw){
  switch ($typeos){
        case '1' { #debian
	  my $qpkg="";
	    $qpkg=`apt-file search "$it_ser"|grep -i "$it_ser\$"|cut -d ":" -f 1`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le fichier système avec droit en ecriture: $it_ser appartient au package:\n";
	      dpkg_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 dpkg_remove($qpkg);
	      }
	    }else{
	      print "Le fichier système avec droit en ecriture: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Fichier système avec droit en ecriture suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
	case '2' { #centos
	  my $qpkg="";
	    $qpkg=`rpm -qf "$it_ser"`;
	    if($qpkg ne ""){
	      print $clear_string; #clearscreen
	      print "Le fichier système avec droit en ecriture: $it_ser appartient au package:\n";
	      rpm_info($qpkg);
	      print "Voulez vous supprimer le package $qpkg? (oui/non) : ";
	      my $input = <STDIN>;
	      if ($input =~ /^yes/i | $input =~ /^oui/i){
		 rpm_remove($qpkg);
	      }
	}else{
	      print "Le fichier système avec droit en ecriture: $it_ser n'appartient a aucun package.\n";
	    }
	  print "Fichier système avec droit en ecriture suivant... (Appuyer sur une touche)\n";
	  my $input = <STDIN>;
	}
  }
}
#lister , fait partie d'un package?
##########################################
#supprimer compte et user/groupe non utils (games, ftp, news, uucp, gopher, ...)

#montage fstab
#ro / rw :Montage en lecture seulement/lecture-écriture
#suid / nosuid :Autorise ou interdit les opérations sur les bits suid et sgid
#dev / nodev :Interprète/n'interprète pas les périphériques caractères ou les périphérique blocs spéciaux sur le système de fichiers
#exec / noexec :Autorise ou interdit l’exécution de fichiers binaires sur ce système de fichiers
#auto / noauto :Le système de fichiers est (c’est l’option par défaut) / n'est pas monté automatiquement
#user / nouser : Permet à tout utilisateur / seulement à root (C’est le paramétrage par défaut) de monter le système de fichiers correspondant
#sync / async :Selon cette valeur, toutes les entrées/sorties se feront en mode synchrone ou asynchrone
#defaults :Utilise le paramétrage par défaut (c’est équivalent à rw, suid, dev, exec, auto, nouser, async)
my @mnt = (
'/boot',
'/tmp',
'/home',
'/var',
'/usr'
#'nfs'
);
my @mnt_droit = (
'nodev,nosuid,noexec',
'nodev,nosuid,noexec',
'nodev,nosuid,noexec',
'nodev,nosuid,noexec',
'nodev,ro'
#'auto,nodev,nosuid,noexec'
);
#boot,tmp,home,var nodev,nosuid,noexec
#usr: ro,odev
for($i=0;$i<=$#mnt;$i++){
  print $clear_string; #clearscreen
  print "Configuration FSTAB\n";
  print "Configuration montage: $mnt[$i]\n";
  my $mnt_act=`grep -iv "^\\s*#" /etc/fstab|grep "$mnt[$i]"|awk '{print \$4}'`;
  $mnt_act=~s/\n//g;
  print "	Montage option: $mnt_act\n";
  if($mnt_act ne $mnt_droit[$i]){
    print "	Voulez vous appliquer les droit suivant: $mnt_droit[$i] ?\n";
    if($mnt_droit[$i] =~ /nodev/i){
      print "		nodev: N'interprète pas les périphériques caractères ou les périphérique blocs spéciaux sur le système de fichiers\n";
    }
    if($mnt_droit[$i] =~ /noexec/i){
      print " 		noexec: Interdit l’exécution de fichiers binaires sur ce système de fichiers\n";
    }
    if($mnt_droit[$i] =~ /nosuid/i){
      print "		nosuid: Interdit les opérations sur les bits suid et sgid\n";
    }
    if($mnt_droit[$i] =~ /ro/i){
      print "		ro: Montage en lecture seulement\n";
    }
    if($mnt_droit[$i] =~ /auto/i){
      print "		auto: Le système de fichiers est monté automatiquement\n";
    }
    print "	Modification FSTAB Oui/Non: ";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
	my $linex=`grep -iEn "^[^\\s*#].*$mnt[$i]" /etc/fstab|cut -d ":" -f 1`;
	$linex=~s/\n//g;
	my $fstab_n=`grep -iv "^\\s*#" /etc/fstab|grep -i "$mnt[$i]"|sed -e 's/$mnt_act/$mnt_droit[$i]/'`;
	$fstab_n=~s/\n//g;
	my $ligne=$linex."i";
	#print "linex==$linex\n";
	$ras=`sed -i.bak '$linex s/^/#/g' /etc/fstab`;
	$ras=`sed -i.bak "$ligne $fstab_n" /etc/fstab`;
    }
  }
  print "Montage suivant... (Appuyer sur une touche)\n";
  my $input = <STDIN>;
}
my $fsnfs=`grep -iE "^[^\\s*#].*\\snfs\\s" /etc/fstab`;
@tmpnfs=split(/\n/,$fsnfs);
my $fsnfs=`grep -iEn "^[^\\s*#].*\\snfs\\s" /etc/fstab |cut -d ":" -f 1`;
@linenfs=split(/\n/,$fsnfs);
my $fsnfs=`grep -iE "^[^\\s*#].*\\snfs\\s" /etc/fstab |awk '{print \$4}'`;
@cfgnfs=split(/\n/,$fsnfs);
for($i=0;$i<=$#tmpnfs;$i++){
  print $clear_string; #clearscreen
  print "Configuration FSTAB NFS: $tmpnfs[$i]\n";
  print "Configuration montage NFS: $cfgnfs[$i]\n";
  if(!($cfgnfs =~ /auto,nodev,nosuid,noexec/i)){
    print "	Voulez vous appliquer les droit suivant: auto,nodev,nosuid,noexec ?\n";
    print "		nodev: N'interprète pas les périphériques caractères ou les périphérique blocs spéciaux sur le système de fichiers\n";
    print " 		noexec: Interdit l’exécution de fichiers binaires sur ce système de fichiers\n";
    print "		nosuid: Interdit les opérations sur les bits suid et sgid\n";
    print "		auto: Le système de fichiers est monté automatiquement\n";
    print "	Modification FSTAB Oui/Non: ";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
	$linenfs[$i]=~s/\n//g;
	$cfgnfs[$i]=~s/\n//g;
	$tmpnfs[$i]=~s/$cfgnfs[$i]/auto,nodev,nosuid,noexec/;
	#print "nfsx==$tmpnfs[$i]\ncfg=$cfgnfs[$i]\n";
	my $ligne=$linenfs[$i]."i";
	$ras=`sed -i.bak '$linenfs[$i] s/^/#/g' /etc/fstab`;
	$ras=`sed -i.bak "$ligne $tmpnfs[$i]" /etc/fstab`;
    }
  }
  print "Montage NFS suivant... (Appuyer sur une touche)\n";
  my $input = <STDIN>;
}
#rajout dpkg dans /etc/apt/apt.config
switch ($typeos){
  case '1' { #debian
    if (-e "/etc/apt/apt.conf.d/12remount") {
      print "Configuration deja installé dans apt...\n";
    } else {
      $ras=` echo 'DPkg {' > /etc/apt/apt.conf.d/12remount`;
      $ras=` echo 'Pre-Invoke {"mount -o remount,rw /usr && mount -o remount,exec /var && mount -o remount,exec /tmp";};' >> /etc/apt/apt.conf.d/12remount`;
      $ras=` echo 'Post-Invoke {"mount -o remount,ro /usr ; mount -o remount,noexec /var && mount -o remount,noexec /tmp";};' >> /etc/apt/apt.conf.d/12remount`;
      $ras=` echo '}' >> /etc/apt/apt.conf.d/12remount`;
    }
  }
  case '2' { #centos
  }
}

#pwck probleme user
$ras=`grep -iv "^\\s*#" /etc/passwd|cut -d ":" -f 1`;
@list_user=split(/\n/,$ras);
for($i=0;$i<=$#list_user;$i++){
  print $clear_string; #clearscreen
  $list_user[$i]=~s/\n//g;
  if(($list_user[$i] eq "root")||($list_user[$i] eq "daemon")){
    next;
  }
  print "Gestion utilisateurs du système\n";
  print "Voici les fichiers appartenant à l'utilisateur $list_user[$i]:\n";
  my $file_user=`find / -user $list_user[$i] -ls 2>/dev/null`;
  print $file_user;
  print "\n	Voulez vous supprimer utilisateur: $list_user[$i]? (Oui/Non)\n";
  my $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
     $ras=`find / -user $list_user[$i] -exec chown root \\{\\} \\;`;
     $ras=`userdel -r $list_user[$i]`;
  }else{
  my $idcmd=`id $list_user[$i]`;
  print "\n	Information id de l'utilisateur: $idcmd";
  print "\n	Voulez vous créer des restrictions sur l'utilisateur: $list_user[$i]? Oui/Non: ";
  print "\n	Vous pouvez par exemple limiter l'utilisation de la memoire pour ssh, postfix ou un autre service ou utilisateur...";
  my $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    #passwd chage
    my $iduser=`id $list_user[$i]|cut -d " " -f 1|sed 's/[^0-9]//g'`;
    if($iduser > 499){
      print $clear_string;
      print "Voulez vous créer des restrictions de password (delai de changement) pour l'utilisateur: $list_user[$i]? Oui/Non: ";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	print "Veuillez entrer le nombre de jours maximum pour le changement de mot de passe: ";
	my $jpm = <STDIN>;
	$jpm =~ s/\n//g;
	print "Veuillez entrer le nombre de jours pour avertire l'utilisateur avant le delai max pour le changement de mot de passe: ";
	my $jpw = <STDIN>;
	$jpw =~ s/\n//g;
	my $cmd = `chage -M $jpm -W $jpw`;
	#chage -M 60 -W 10 -> l'utilisateur doit changer de mot de passe tout les 60jours et il est prevenu 10jours avant 
      }
    }
    #CGROUPS : memory + cpu + device
    #/etc/cgconfig.conf
    #mount {
    #   cpu = /sys/fs//cgroup/cpu; 
    #	cpuacct = /sys/fs//cgroup/cpuacct; 
    #	memory = /sys/fs/cgroup/memory;
    #	devices = /sys/fs/cgroup/devices; # https://www.kernel.org/doc/Documentation/devices.txt sample b & c 180:* == usb
    #}
    # IO > group groupname { cpu {} cpuacct {} memory { memory.limit_in_bytes=; memory.memsw.limit_in_bytes=;} devices {} }
    # echo "user memory groupename" /etc/cgrules.conf  & reload cgred daemon
    # ref http://uubu.fr/spip.php?article295
    if($cgroupsacten== 1){
      print $clear_string;
      print "Restrictions/statistiques Cgroups: memoire, cpu, devices.\n";
      print "Pour plus d\informations sur les cgroups vous pouvez visiter: http://uubu.fr/spip.php?article295\n";
      print "CPU: permet de limiter le temps CPU (cpu.share) mais la partie cpuacct permet de faire des statistiques de l'utilisation cpu de vos applis.\n";
      print "Memory: permet de limiter l'utilisation de la memoire ram & swap ainsi que de realiser des statistiques.\n";
      print "Devices: permet de limiter l'accès au devices pour les applications lancés sous le cgroups. ref. device: https://www.kernel.org/doc/Documentation/devices.txt\n";
      print "Voulez vous créer des restrictions Cgroups pour l'utilisateur: $list_user[$i]? Oui/Non: ";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	#debian pkg: cgroup-bin libcgroup1
	print $clear_string; #clearscreen
	my $free=`free -m -t`;
	print "Information sur votre ram et swap en MO:\n$free\n";
	print "Veuillez indiquer la taille de memoire ram maximum pour l'utilisateur (rajouter M ou G a la fin si en MO ou GO): ";
	my $memrl = <STDIN>;
	$memrl =~ s/\n//g;
	print "Veuillez indiquer la taille de memoire ram + swap maximum pour l'utilisateur (rajouter M ou G a la fin si en MO ou GO): ";
	my $memrsl = <STDIN>;	
	$memrsl =~ s/\n//g;
	my $cit_prouser=$user_list[i]."_cgroups";
	$ras=`if(grep "group $cit_prouser" /etc/cgconfig.conf);then echo CGROUPOK;else echo CGROUPKO;fi`;
	if($ras=~/CGROUPOK/){
		print "Le groupe $cit_prouser dans /etc/cgconfig.conf existe deja!";
	} else {
		$ras=`echo "group $cit_prouser { cpu {} cpuacct {} memory { memory.limit_in_bytes=$memrl; memory.memsw.limit_in_bytes=$memrsl;} devices {} }" >> /etc/cgconfig.conf`;
		$ras=`echo "$user_list[i] memory $cit_prouser" >> /etc/cgrules.conf`;
		#restart deamon cg!!!!!!!!!!!!
		$ras=`/etc/init.d/cgconfig restart;/etc/init.d/cgred restart`;
	} 
      }
    }
    #Ulimit: proc max, max ouverture session, max open file, max size file
    print $clear_string;
    my $limitS=`su - $list_user[$i] -c ulimit -a`;
    my $limitH=`su - $list_user[$i] -c ulimit -Ha`;
    print $clear_string;
    print "Ulimit - Limites actuelles pour l'utilisateur: $list_user[$i]\n";
    print " Soft:\n$limitS\n Hard:\n$limitH\n";
    print "Restriction Ulimit: proc max, max ouverture session, max open file, max size file.\n";
    print "Voulez vous créer des restrictions Ulimit pour l'utilisateur: $list_user[$i]? Oui/Non: ";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      print $clear_string;
      $limitS=`su - $list_user[$i] -c ulimit -u`;
      $limitH=`su - $list_user[$i] -c ulimit -Hu`;
      print "Voulez vous modifier la configuration sur le nombre de proc maximum pour l'utilisateur $list_user[$i]? (actuel : $limitS / [hard] $limitH) (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  my $aide=`ps haux Ou | cut '-d ' -f1 | uniq -c`; # get number de process par user
	  print "Indication pour aide: nombre process/user\n$aide\n";
	  print "Veuillez entrer le nombre de proc maximum pour l'utilisateur $list_user[$i] (soft): (laissez vide si aucune)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer le nombre de proc maximum pour l'utilisateur $list_user[$i] (hard): (laissez vide si aucune)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_user[$i]\\s*soft\\s*nproc" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_user[$i]\\s*soft\\s*nproc" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_user[$i] hard nproc $hard";
	  my $softl="$list_user[$i] soft nproc $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
      print $clear_string;
      print "Voulez vous modifier la configuration sur le nombre d'ouverture de session maximum pour l'utilisateur $list_user[$i] (maxlogins)? (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  print "Commande d'aide \"who -u\"...\n";
	  print "Veuillez entrer le nombre d'ouverture de session maximum pour l'utilisateur $list_user[$i] (soft): (laissez vide si aucune - valeur aide: 1 ou 2)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer le nombre d'ouverture de session maximum pour l'utilisateur $list_user[$i] (hard): (laissez vide si aucune - valeur aude: max 4)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_user[$i]\\s*soft\\s*maxlogins" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_user[$i]\\s*soft\\s*maxlogins" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_user[$i] hard maxlogins $hard";
	  my $softl="$list_user[$i] soft maxlogins $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
      $limitS=`su - $list_user[$i] -c ulimit -n`;
      $limitH=`su - $list_user[$i] -c ulimit -Hn`;
      print $clear_string;
      print "Voulez vous modifier la configuration sur le nombre d'ouverture de fichier maximum pour l'utilisateur $list_user[$i] (nofile)? (actuel : $limitS / [hard] $limitH) (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  my $aide=`lsof -u root | wc -l`; 
	  print "Indication pour aide (lsof -u uid): nombre file open pour root -> $aide\n";
	  print "Veuillez entrer le nombre d'ouverture de fichier maximum pour l'utilisateur $list_user[$i] (soft): (laissez vide si aucune)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer le nombre d'ouverture de fichier maximum pour l'utilisateur $list_user[$i] (hard): (laissez vide si aucune)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_user[$i]\\s*soft\\s*nofile" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_user[$i]\\s*soft\\s*nofile" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_user[$i] hard nofile $hard";
	  my $softl="$list_user[$i] soft nofile $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
      $limitS=`su - $list_user[$i] -c ulimit -f`;
      $limitH=`su - $list_user[$i] -c ulimit -Hf`;
      print $clear_string;
      print "Voulez vous modifier la configuration sur la taille maximum d'un fichier (fsize)? (actuel : $limitS / [hard] $limitH) (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  print "Veuillez entrer la taille maximum d'un fichier pour l'utilisateur $list_user[$i] (soft): (laissez vide si aucune)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer la taille maximum d'un fichier pour l'utilisateur $list_user[$i] (hard): (laissez vide si aucune)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_user[$i]\\s*soft\\s*fsize" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_user[$i]\\s*soft\\s*fsize" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_user[$i] hard fsize $hard";
	  my $softl="$list_user[$i] soft fsize $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
    }
  }
 }
}
print "Appuyer sur une touche pour continuer...\n";
my $input = <STDIN>;
$ras=`grep -iv "^\\s*#" /etc/group|cut -d ":" -f 1`;
@list_group=split(/\n/,$ras);
#lister les fichier appartenant a l'utilisateur/groupe a supprimer puis passé a root
for($i=0;$i<=$#list_group;$i++){
  print $clear_string; #clearscreen
  $list_group[$i]=~s/\n//g;
  if(($list_group[$i] eq "root")||($list_group[$i] eq "wheel")||($list_group[$i] eq "daemon")||($list_group[$i] eq "nogroup")){
    next;
  }
  print "Gestion des groupes du système\n";
  print "Voici les fichiers appartenant au groupe $list_group[$i]:\n";
  my $file_group=`find / -group $list_group[$i] -ls 2>/dev/null`;
  print $file_group;
  print "\n	Voulez vous supprimer le groupe: $list_group[$i]? Oui/Non: ";
  my $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    $ras=`find / -group $list_group[$i] -exec chgrp root \\{\\} \\;`;
    $ras=`groupdel $list_group[$i]`;
  }else {
  print "\n	Voulez vous créer des restrictions sur le groupe: $list_group[$i]? Oui/Non: ";
  my $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
    #CGROUPS : memory + cpu
    if($cgroupsacten == 1){
      print $clear_string;
      print "Restriction Cgroups: memoire et cpu.\n";
      print "Voulez vous créer des restrictions Cgroups pour le groupe: $list_group[$i]? Oui/Non: ";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	#debian pkg: cgroup-bin libcgroup1
	print $clear_string; #clearscreen
	my $free=`free -m -t`;
	print "Information sur votre ram et swap en MO:\n$free\n";
	print "Veuillez indiquer la taille de memoire ram maximum pour le groupe (rajouter M ou G a la fin si en MO ou GO): ";
	my $memrl = <STDIN>;
	$memrl =~ s/\n//g;
	print "Veuillez indiquer la taille de memoire ram + swap maximum pour le groupe (rajouter M ou G a la fin si en MO ou GO): ";
	my $memrsl = <STDIN>;	
	$memrsl =~ s/\n//g;
	my $cit_prouser=$list_group[$i]."_grp_cgroups";
	my $cit_grp="\@".$list_group[$i];
	$ras=`if(grep "group $cit_prouser" /etc/cgconfig.conf);then echo CGROUPOK;else echo CGROUPKO;fi`;
	if($ras=~/CGROUPOK/){
		print "Le groupe $cit_prouser dans /etc/cgconfig.conf existe deja!";
	} else {
		$ras=`echo "group $cit_prouser { cpu {} cpuacct {} memory { memory.limit_in_bytes=$memrl; memory.memsw.limit_in_bytes=$memrsl;} devices {} }" >> /etc/cgconfig.conf`;
		$ras=`echo "$cit_grp memory $cit_prouser" >> /etc/cgrules.conf`;
		#restart deamon cg!!!!!!!!!!!!
		$ras=`/etc/init.d/cgconfig restart;/etc/init.d/cgred restart`;
	} 
      }
    }
    #Ulimit: proc max, max ouverture session, max open file, max size file
    print $clear_string;
    print "Restriction Ulimit: proc max, max ouverture session, max open file, max size file.\n";
    print "Voulez vous créer des restrictions Ulimit pour le groupe: $list_group[$i]? Oui/Non: ";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      print $clear_string;
      print "Voulez vous modifier la configuration sur le nombre de proc maximum pour le groupe $list_group[$i]? (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  my $aide=`ps haux Ou | cut '-d ' -f1 | uniq -c`; # get number de process par user
	  print "Indication pour aide: nombre process/user\n$aide\n";
	  print "Veuillez entrer le nombre de proc maximum pour le groupe $list_group[$i] (soft): (laissez vide si aucune)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer le nombre de proc maximum pour le groupe $list_group[$i] (hard): (laissez vide si aucune)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_group[$i]\\s*soft\\s*nproc" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_group[$i]\\s*soft\\s*nproc" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_group[$i] hard nproc $hard";
	  my $softl="$list_group[$i] soft nproc $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
      print $clear_string;
      print "Voulez vous modifier la configuration sur le nombre d'ouverture de session maximum pour le groupe $list_group[$i] (maxlogins)? (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  print "Commande d'aide \"who -u\"...\n";
	  print "Veuillez entrer le nombre d'ouverture de session maximum pour le groupe $list_group[$i] (soft): (laissez vide si aucune - valeur aide: 1 ou 2)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer le nombre d'ouverture de session maximum pour le groupe $list_group[$i] (hard): (laissez vide si aucune - valeur aude: max 4)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_group[$i]\\s*soft\\s*maxlogins" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_group[$i]\\s*soft\\s*maxlogins" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_group[$i] hard maxlogins $hard";
	  my $softl="$list_group[$i] soft maxlogins $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
      print $clear_string;
      print "Voulez vous modifier la configuration sur le nombre d'ouverture de fichier maximum pour le groupe $list_group[$i] (nofile)? (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  my $aide=`lsof -u root | wc -l`; 
	  print "Indication pour aide (lsof -u uid): nombre file open pour root -> $aide\n";
	  print "Veuillez entrer le nombre d'ouverture de fichier maximum pour le groupe $list_group[$i] (soft): (laissez vide si aucune)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer le nombre d'ouverture de fichier maximum pour le groupe $list_group[$i] (hard): (laissez vide si aucune)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_group[$i]\\s*soft\\s*nofile" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_group[$i]\\s*soft\\s*nofile" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_group[$i] hard nofile $hard";
	  my $softl="$list_group[$i] soft nofile $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
      print $clear_string;
      print "Voulez vous modifier la configuration sur la taille maximum d'un fichier (fsize)? (Oui/Non)";
      my $input = <STDIN>;
      if ($input =~ /^yes/i | $input =~ /^oui/i){
	  print "Veuillez entrer la taille maximum d'un fichier pour le groupe $list_group[$i] (soft): (laissez vide si aucune)\n";
	  my $soft = <STDIN>;
	  $soft =~ s/\n//g;
	  print "Veuillez entrer la taille maximum d'un fichier pour le groupe $list_group[$i] (hard): (laissez vide si aucune)\n";
	  my $hard = <STDIN>;
	  $hard =~ s/\n//g;
	  my $lconf=`grep -iEnm 1 "^\\s*$list_group[$i]\\s*soft\\s*fsize" /etc/security/limits.conf | cut -d ":" -f 1`;
	  my $lconfd=`grep -iERnm 1 "^\\s*$list_group[$i]\\s*soft\\s*fsize" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
	  $lconf=~s/\n//g;
	  $lconfd=~s/\n//g;
	  $soft=~s/\n//g;
	  $hard=~s/\n//g;
	  my $hardl="$list_group[$i] hard fsize $hard";
	  my $softl="$list_group[$i] soft fsize $soft";
	  if(lconf =~ /[0-9]/i){
	    $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  } elsif(lconfd =~ /[0-9]/i){
	    my ($nl1,$ll1)=split(/:/,$lconfd);
	    $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
	    $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
	  } else{
	    $ras=`echo "$softl" >> /etc/security/limits.conf`;
	  }
      }
    }
  }
 }
}
##########################################
#LIMITER tous le monde:
# - ulimit (voir ulimit -a et ulimit-Ha)
# - mot de passe limitation taille et redondance
#!!!!!!!!!!!!!!!CGROUPS pour root?
my $limitS=`ulimit -a`;
my $limitH=`ulimit -Ha`;
print $clear_string;
print "Limits.conf - Limites actuelles:\n";
print " Soft:\n$limitS\n Hard:\n$limitH\n";
print "Appuyer sur une touche pour continuer...";
my $input = <STDIN>;
print $clear_string;
$limitS=`ulimit -u`;
$limitH=`ulimit -Hu`;
print "Voulez vous modifier la configuration sur le nombre de proc maximum par utilisateur? (actuel : $limitS / [hard] $limitH) (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
    my $aide=`ps haux Ou | cut '-d ' -f1 | uniq -c`; # get number de process par user
    print "Indication pour aide: nombre process/user\n$aide\n";
    print "Veuillez entrer le nombre de proc maximum par utilisateur (soft): (laissez vide si aucune)\n";
    my $soft = <STDIN>;
    $soft =~ s/\n//g;
    print "Veuillez entrer le nombre de proc maximum par utilisateur (hard): (laissez vide si aucune)\n";
    my $hard = <STDIN>;
    $hard =~ s/\n//g;
    my $lconf=`grep -iEnm 1 "^\\s*\\*\\s*soft\\s*nproc" /etc/security/limits.conf | cut -d ":" -f 1`;
    my $lconfd=`grep -iERnm 1 "^\\s*\\*\\s*soft\\s*nproc" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
    $lconf=~s/\n//g;
    $lconfd=~s/\n//g;
    $soft=~s/\n//g;
    $hard=~s/\n//g;
    my $hardl="* hard nproc $hard";
    my $softl="* soft nproc $soft";
    if(lconf =~ /[0-9]/i){
      $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    } elsif(lconfd =~ /[0-9]/i){
      my ($nl1,$ll1)=split(/:/,$lconfd);
      $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
      $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
    } else{
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    }
}
print $clear_string;
print "Voulez vous modifier la configuration sur le nombre d'ouverture de session maximum par utilisateur (hors root - maxlogins)? (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
    print "Commande d'aide \"who -u\"...\n";
    print "Veuillez entrer le nombre d'ouverture de session maximum par utilisateur (soft): (laissez vide si aucune - valeur aide: 1 ou 2)\n";
    my $soft = <STDIN>;
    $soft =~ s/\n//g;
    print "Veuillez entrer le nombre d'ouverture de session maximum par utilisateur (hard): (laissez vide si aucune - valeur aude: max 4)\n";
    my $hard = <STDIN>;
    $hard =~ s/\n//g;
    my $lconf=`grep -iEnm 1 "^\\s*\\*\\s*soft\\s*maxlogins" /etc/security/limits.conf | cut -d ":" -f 1`;
    my $lconfd=`grep -iERnm 1 "^\\s*\\*\\s*soft\\s*maxlogins" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
    $lconf=~s/\n//g;
    $lconfd=~s/\n//g;
    $soft=~s/\n//g;
    $hard=~s/\n//g;
    my $hardl="* hard maxlogins $hard";
    my $softl="* soft maxlogins $soft";
    if(lconf =~ /[0-9]/i){
      $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    } elsif(lconfd =~ /[0-9]/i){
      my ($nl1,$ll1)=split(/:/,$lconfd);
      $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
      $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
    } else{
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    }
}
$limitS=`ulimit -n`;
$limitH=`ulimit -Hn`;
print $clear_string;
print "Voulez vous modifier la configuration sur le nombre d'ouverture de fichier maximum (nofile)? (actuel : $limitS / [hard] $limitH) (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
    my $aide=`lsof -u root | wc -l`; 
    print "Indication pour aide (lsof -u uid): nombre file open pour root -> $aide\n";
    print "Veuillez entrer le nombre d'ouverture de fichier maximum par utilisateur (soft): (laissez vide si aucune)\n";
    my $soft = <STDIN>;
    $soft =~ s/\n//g;
    print "Veuillez entrer le nombre d'ouverture de fichier maximum par utilisateur (hard): (laissez vide si aucune)\n";
    my $hard = <STDIN>;
    $hard =~ s/\n//g;
    my $lconf=`grep -iEnm 1 "^\\s*\\*\\s*soft\\s*nofile" /etc/security/limits.conf | cut -d ":" -f 1`;
    my $lconfd=`grep -iERnm 1 "^\\s*\\*\\s*soft\\s*nofile" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
    $lconf=~s/\n//g;
    $lconfd=~s/\n//g;
    $soft=~s/\n//g;
    $hard=~s/\n//g;
    my $hardl="* hard nofile $hard";
    my $softl="* soft nofile $soft";
    if(lconf =~ /[0-9]/i){
      $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    } elsif(lconfd =~ /[0-9]/i){
      my ($nl1,$ll1)=split(/:/,$lconfd);
      $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
      $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
    } else{
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    }
}
$limitS=`ulimit -f`;
$limitH=`ulimit -Hf`;
print $clear_string;
print "Voulez vous modifier la configuration sur la taille maximum d'un fichier (fsize)? (actuel : $limitS / [hard] $limitH) (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
    print "Veuillez entrer la taille maximum d'un fichier par utilisateur (soft): (laissez vide si aucune)\n";
    my $soft = <STDIN>;
    $soft =~ s/\n//g;
    print "Veuillez entrer la taille maximum d'un fichier par utilisateur (hard): (laissez vide si aucune)\n";
    my $hard = <STDIN>;
    $hard =~ s/\n//g;
    my $lconf=`grep -iEnm 1 "^\\s*\\*\\s*soft\\s*fsize" /etc/security/limits.conf | cut -d ":" -f 1`;
    my $lconfd=`grep -iERnm 1 "^\\s*\\*\\s*soft\\s*fsize" /etc/security/limits.d/ | awk -F ":" '{print \$1":"\$2}'`;
    $lconf=~s/\n//g;
    $lconfd=~s/\n//g;
    $soft=~s/\n//g;
    $hard=~s/\n//g;
    my $hardl="* hard fsize $hard";
    my $softl="* soft fsize $soft";
    if(lconf =~ /[0-9]/i){
      $ras=`sed -i.bak '$lconf s/^/#/g' /etc/security/limits.conf`;
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    } elsif(lconfd =~ /[0-9]/i){
      my ($nl1,$ll1)=split(/:/,$lconfd);
      $ras=`sed -i.bak '$ll1 s/^/#/g' /etc/security/limits.d/$nl1`;
      $ras=`echo "$softl" >> /etc/security/limits.d/$nl1`;
    } else{
      $ras=`echo "$softl" >> /etc/security/limits.conf`;
    }
}

if(-e "/etc/cron.deny"){
  if(-e "/etc/cron.allow"){
    print $clear_string;
    my $cronal=`cat /etc/cron.allow|tr "\\n" " "`;
    my $cronde=`cat /etc/cron.deny|tr "\\n" " "`;
    print "CRONTAB: Liste des utilisateurs autorisés: root $cronal\n Liste des utilisateurs non autorisés: $cronde\n";
    print "Voulez vous restreindre l'acces à root? (Oui/Non)";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      my $cmd_cron=`mv /etc/cron.allow /etc/cron.allow.old`;
      my $cmd_cron=`mv /etc/cron.deny /etc/cron.deny.old`;
    }
  } else {
    print $clear_string;
    print "CRONTAB: Tous le monde peut installer des crontab...\n";
    print "Voulez vous restreindre l'acces à root? (Oui/Non)";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      my $cmd_cron=`mv /etc/cron.deny /etc/cron.deny.old`;
    }
  }
} else {
  if(-e "/etc/cron.allow"){
    print $clear_string;
    my $cronal=`cat /etc/cron.allow|tr "\\n" " "`;
    print "CRONTAB: seul root et les utilisateurs suivant peuvent installer des crontab: $cronal\n";
    print "Voulez vous restreindre l'acces à root? (Oui/Non)";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      my $cmd_cron=`mv /etc/cron.allow /etc/cron.allow.old`;
    }
  } else {
    print $clear_string;
    print "CRONTAB: seul root est autorisé à installer des crontab\n";
    print "Appuyer sur une touche pour continuer...";
    my $input = <STDIN>;
  }
}

if(-e "/etc/at.deny"){
  if(-e "/etc/at.allow"){
    print $clear_string;
    my $cronal=`cat /etc/at.allow|tr "\\n" " "`;
    my $cronde=`cat /etc/at.deny|tr "\\n" " "`;
    print "AT: Liste des utilisateurs autorisés: root $cronal\n Liste des utilisateurs non autorisés: $cronde\n";
    print "Voulez vous restreindre l'acces à root? (Oui/Non)";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      my $cmd_cron=`mv /etc/at.allow /etc/at.allow.old`;
      my $cmd_cron=`mv /etc/at.deny /etc/at.deny.old`;
    }
  } else {
    print $clear_string;
    print "AT: Tous le monde peut lancer des applications avec AT...\n";
    print "Voulez vous restreindre l'acces à root? (Oui/Non)";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      my $cmd_cron=`mv /etc/at.deny /etc/at.deny.old`;
    }
  }
} else {
  if(-e "/etc/at.allow"){
    print $clear_string;
    my $cronal=`cat /etc/at.allow|tr "\\n" " "`;
    print "AT: seul root et les utilisateurs suivant peuvent lancer des applications avec AT: $cronal\n";
    print "Voulez vous restreindre l'acces à root? (Oui/Non)";
    my $input = <STDIN>;
    if ($input =~ /^yes/i | $input =~ /^oui/i){
      my $cmd_cron=`mv /etc/at.allow /etc/at.allow.old`;
    }
  } else {
    print $clear_string;
    print "AT: seul root est autorisé à lancer des applications avec AT\n";
    print "Appuyer sur une touche pour continuer...";
    my $input = <STDIN>;
  }
}

print $clear_string;
my $issue=`cat /etc/issue`;
print "Le contenue de /etc/issue (message d'acceuil avant l'authentification) est:\n$issue\n";
print "Voulez vous modifier le texte contenue dans issue? (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
      print $clear_string;
      $issue=`mv /etc/issue /etc/issue.old`;
      print "Veuillez entrer le nouveau texte (puis EOF pour finir):\n";
      $fh = new IO::File;
      $fh->open("/etc/issue","w");
      if (defined $fh) {
        while (<STDIN>) {                   # reads from STDIN
                if($_ =~ /^EOF/i){
                        last;
                }
                print $fh $_;          
        }
        $fh->close;
    }
}
print $clear_string;
my $motd=`cat /etc/motd`;
print "Le contenue de /etc/motd (message d'acceuil apres connexion avant le shell) est:\n$motd\n";
print "Voulez vous modifier le texte contenue dans motd? (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
      print $clear_string;
      $motd=`mv /etc/motd /etc/motd.old`;
      print "Veuillez entrer le nouveau texte (puis EOF pour finir):\n";
      $fh = new IO::File;
      $fh->open("/etc/motd","w");
      if (defined $fh) {
        while (<STDIN>) {                   # reads from STDIN
                if($_ =~ /^EOF/i){
                        last;
                }
                print $fh $_;             
        }
        $fh->close;
    }
}

#chage command pour voir et changer les obligation sur les password des utilisateurs
#limitation du shell dans passwd
#modifier change max day & minimum taille du passe & verification pour ne pas remettre l'ancien passwd

#limiter le root via le reseau /etc/securetty limiter a tty1 commenter tout le reste
print $clear_string;
print "Voulez vous restreindre l'acces a l'ouverture de session du root au TTY1? (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  my $ttylim=`sed  -i.bak '/[^tty1]/ s/^/#/'  /etc/securetty`;
}

#limiter le su a certains user: /etc/pam.d/su: auth required   /lib/security/pam_wheel.so  group=wheel
my $test_su=`grep -v "^#" /etc/pam.d/su|grep -i "pam_wheel"`;
if ($test_su =~ /wheel/i){
  print $clear_string;
  $verif=`getent group wheel |awk -F ":" '{print \$NF}'`;
  print "Restriction de la commande SU activé sur le groupe wheel.\nListe des utilisateurs du groupe wheel: $user\n";
  print "Appuyer sur une touche pour continuer...";
  my $input = <STDIN>;
} else {
  print $clear_string;
  print "Voulez vous limiter l'acces a la commande su au groupe wheel (config user)? (Oui/Non)";
  my $input = <STDIN>;
  if ($input =~ /^yes/i | $input =~ /^oui/i){
  #verification existance du groupe
  #demande qui doit etre mis dedans
    while(1){
      print $clear_string;
      $ras=`groupadd -r wheel;usermod -a -G wheel root`;
      $verif=`getent group wheel |awk -F ":" '{print \$NF}'`;
      print "Voici la liste des utilisateurs faisant partie du groupe wheel: $verif\n";
      $verif=`grep "^[^#]" /etc/passwd |awk -F ":" '{print \$1}'|tr "\\n" " "`;
      print "Voici la liste des utilisateurs: $verif\n";
      print "Entrer le nom de l'utilisateur a rajouter dans la liste du groupe wheel (ou quit si vous avez fini):\n";
      my $user = <STDIN>;
      $user =~ s/\n//g;
      if ($user =~ /^quit/i){
	last;
      } else {
	my $ret=`usermod -a -G wheel $user`;
      }	
    }
  #ajout du groupe dans pam.d/su
  my $add_su=`if(grep -i "^auth required pam_wheel.so use_uid" /etc/pam.d/su);then echo "ok";else echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su;fi`;
  }
}

#limiter logindefs et pam limit

#eviter une reboot par ctrl+alt+suppr: /etc/inittab #ca::ctrlaltdel:/sbin/shutdown -t3 -r now
#sed  -i.bak '/ctrlaltdel/ s/^/#/'  /etc/inittab
print $clear_string;
print "Voulez vous restreindre l'extinction du serveur (ACPI & ctrlaltdel)? (Oui/Non)";
my $input = <STDIN>;
if ($input =~ /^yes/i | $input =~ /^oui/i){
  my $ctrlaltdel=`sed  -i.bak '/ctrlaltdel/ s/^/#/'  /etc/inittab`;
  $ctrlaltdel=`/etc/init.d/acpid stop`;
  switch ($typeos) {
        case '1' { #debian
	  $ctrlaltdel=`update-rc.d acpid disable`;
	}
        case '2' { #centos
	  $ctrlaltdel=`chkconfig acpid off`;
	}
  }
}
#PASS_MAX_DAYS
#PASS_MIN_LEN
##########################################
#CGROUPS -> restreindre la memoire et l'usage du cpu, permet d'obtenir des stats d'utilisation pour un user, group ou proc
#http://uubu.fr/spip.php?article295 < possibilité offert par cgroups
#limitation memoire par user
#http://blog.hbis.fr/2012/01/16/debian-webserver_and_cgroups/
#https://www.kernel.org/doc/Documentation/cgroups/memory.txt 
#installation outils cgroups-utils
#creation des limitation dans  /etc/cgconfig.conf
#ref https://access.redhat.com/site/documentation/fr-FR/Red_Hat_Enterprise_Linux/6/html/Resource_Management_Guide/ch-Using_Control_Groups.html
#creation de liens entre cgroup et group linux /etc/cgrules.conf 
#https://access.redhat.com/site/documentation/fr-FR/Red_Hat_Enterprise_Linux/6/html/Resource_Management_Guide/sec-Moving_a_Process_to_a_Control_Group.html
##########################################
#netatop permet la creation d'analyse comportemental sur des durée et taille d'echange
##########################################
#GRUB PASSWD + reboot protection
#4.8 Restricting system reboots through the console
#
#If your system has a keyboard attached to it anyone (yes anyone) with physical access to the system can reboot the system through it without login in just pressing the Ctrl+Alt+Delete keyboard combination, also known as the three finger salute. This might, or might not, adhere to your security policy.
#
#This is aggravated in environments in which the operating system is running virtualised. In these environments, the possibility extends to users that have access to the virtual console (which might be accessed over the network). Also note that, in these environments, this keyboard combination is used constantly (to open a login shell in some GUI operating systems) and an administrator might virtually send it and force a system reboot.
#
#There are two ways to restrict this:
#
#configure it so that only allowed users can reboot the system,
#
#disable this feature completely.
##########################################
#installation lxc et securisation pour service avec drbd ipsec
#avec regle sandbox?
#http://www.thomas-krenn.com/en/wiki/HA_Cluster_with_Linux_Containers_based_on_Heartbeat,_Pacemaker,_DRBD_and_LXC
##########################################
#NRPE supervision & cacti
#regle comportemental avec cacti (log taille, connexion, ...)
##########################################
#Creation snort IDS & oink
##########################################
#remonté vers OSSIM
##########################################

### save iptablES!!!
#iptables save and reload on start
print "IPTABLES SAVE FINAL...";
switch ($typeos) {
  case '1' { #debian
    $iptablesave=`iptables-save > /etc/iptables/rules`;
    print "Sauveguarde de la configuration iptables dans: /etc/iptables/rules\n";
  }
  case '2' { #centos
    $iptablesave=`iptables-save > /etc/iptables.rules;iptables-save > /etc/sysconfig/iptables`;
  }
}
print "OK.\nAppuyer sur une touche pour continuer.";
$input = <STDIN>;
print "Afin que la configuration soit bien prise en compte sur tous les paramètres mis en place, veuillez rebooter le serveur...\n";
print "Merci d'avoir utiliser le script de securisation linux serveur!\n Bye";
exit;
