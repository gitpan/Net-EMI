package Net::EMI;
use strict;
#
# Copyright (c) 2001,2002 Jochen Schneider <jochen.schneider@mediaways.net>.
# Copyright (c) 2002 Gustav Schaffter.
# All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use vars qw($VERSION);
$VERSION='0.9.2';

use IO::Socket;

use constant STX=>chr(2);     # start transmission
use constant ETX=>chr(3);     # end transmission
use constant SLASH=>'/';      # ucp delimiter
use constant TRUE=>1;

###########################################################################################################
sub new {
   my$self={};
   bless($self,shift())->_init(@_);
}

###########################################################################################################
# login to SMSC
sub login {
   my($self,$OadC,$password)=@_;

   # Conditionally open the socket unless already opened.
   $self->open_link() unless(defined($self->{SOCK}));
   return(undef) unless(defined($self->{SOCK}));

	my $data=$OadC.
	         SLASH.
	         '6'.     # OTON (short number alias)
	         SLASH.
	         '5'.     # ONPI (private)
	         SLASH.
	         '1'.     # STYP (open session)
	         SLASH.
	         $self->_ia5_encode($password).
	         SLASH.
	         ''.      # NPWD
	         SLASH.
	         '0100'.  # VERS (version)
	         SLASH.
	         ''.      # LAdC
	         SLASH.
	         ''.      # LTON
	         SLASH.
	         ''.      # LNPI
	         SLASH.
	         ''.      # OPID
	         SLASH.
	         '';      # RES1

	my $header=sprintf("%02d",$self->{TRN}++).   # Transaction counter.
	           SLASH.
	           $self->_data_len($data).          # Length.
	           SLASH.
	           'O'.                              # Type (operation).
	           SLASH.
	           '60';                             # OT (submit message).

	my $checksum=$self->_checksum($header.SLASH.$data.SLASH);
	$self->_transmit_msg($header.SLASH.$data.SLASH.$checksum);
}

#############################################################################################
# This method will also conditionally be called from the login() method.
sub open_link {
   my$self=shift;

   $self->{SOCK}=IO::Socket::INET->new(PeerAddr=>$self->{HOST},
                                       PeerPort=>$self->{PORT},
                                       Proto=>'tcp');
   defined($self->{SOCK})||do {
      # Error handling can and will be improved here.
      warn("Failed to establish a socket connection with host $self->{HOST} on port $self->{PORT} ");
      return(undef);
   };
   TRUE;
}

#############################################################################################
# To avoid keeping the socket open if not used any more.
sub close_link {
   my$self=shift;

   close($self->{SOCK});
   $self->{SOCK}=undef;
   $self->{TRN}=0;
   TRUE;
}

###########################################################################################################
# send the SMS
sub send_sms {
   my($self,$AdC,$message)=@_;

   defined($AdC)||return(undef);
   defined($message)||($message='');

	$AdC=~s/^\+/00/;
	$AdC=~/^\d+$/||do{
	   warn("The adress contains illegal (non-numerical) characters: $AdC\nMessage not sent ");
	   return(undef);
	};

   # Using this value, all message will come from 'Mediaways'.
   # A future version will make it possible to configure this value.
	my $OAdC = '10ED32391DBE87F373';# Adress Code originator

	my $data=$AdC.
	         SLASH.
	         $OAdC.
	         SLASH.
	         ''.         # $AC.
	         SLASH.
	         ''.         # NRq (Notfication Request 1).
	         SLASH.
	         ''.         # $NAdC.
	         SLASH.
	         ''.         # NT (Notification Type 3).
	         SLASH.
	         ''.         # $NPID.
	         SLASH.
	         ''.         # $LRq.
	         SLASH.
	         ''.         # LRAd (Last Resort Address).
	         SLASH.
	         ''.         # $LPID.
	         SLASH.
	         ''.         # $DD.
	         SLASH.
	         ''.         # $DDT.
	         SLASH.
	         ''.         # $VP.
	         SLASH.
	         ''.         # $RPID.
	         SLASH.
	         ''.         # $SCTS.
	         SLASH.
	         ''.         # $Dst.
	         SLASH.
	         ''.         # $Rsn.
	         SLASH.
	         ''.         # $DSCTS.
	         SLASH.
	         '3'.        # MT (message type, alphanumeric).
	         SLASH.
	         ''.         # $NB.
	         SLASH.
	         $self->_ia5_encode($message).
	         SLASH.
	         ''.         # $MMS.
	         SLASH.
	         ''.         # $PR.
	         SLASH.
	         ''.         # $DCs.
	         SLASH.
	         ''.         # $MCLs.
	         SLASH.
	         ''.         # $RPI.
	         SLASH.
	         ''.         # $CPg.
	         SLASH.
	         ''.         # $RPLy.
	         SLASH.
	         '5039'.     # OTOA (Originator Type of Address).
	         SLASH.
	         ''.         # $HPLMN.
	         SLASH.
	         ''.         # $XSer.
	         SLASH.
	         ''.         # $RES4.
	         SLASH.
	         '';         # $RES5;

	my $header=sprintf("%02d",$self->{TRN}++). # Transaction counter.
	           SLASH.
	           $self->_data_len($data).
	           SLASH.
	           'O'.      # Type.
	           SLASH.
	           '51';     # OT (submit message)

	my $message_string=$header.
	                   SLASH.
	                   $data.
	                   SLASH.
	                   $self->_checksum($header.
	                                    SLASH.
	                                    $data.
	                                    SLASH);

	# print($message_string,"\n");
	$self->_transmit_msg($message_string);
}

###########################################################################################################
###########################################################################################################
#
# 'Internal' subs. Don't call these, since they may, and will, change without notice.
#
###########################################################################################################
###########################################################################################################

###########################################################################################################
sub _init {
   my($self,$host,$port)=@_;

   defined($host)||do{
      warn("Mandatory variable 'host' was missing when creating and object of class ".__PACKAGE__.". Object not created ");
      return(undef);       # Failed to instantiate this object.
   };
   defined($port)||do{
      warn("Mandatory variable 'port' was missing when creating and object of class ".__PACKAGE__.". Object not created ");
      return(undef);       # Failed to instantiate this object.
   };

   $self->{HOST}=$host;
   $self->{PORT}=$port;
   $self->{SOCK}=undef;
   $self->{TRN}=0;         # Transaction number.

   $self;
}

###########################################################################################################
#sub _ia5_decode {
#   my($self,$message)=@_;
#
#	for($i=0;$i<=length($message);$i+=2) {
#		$decoded.=chr(hex(substr($message,$i,2)));
#	}
#	$decoded;
#}

###########################################################################################################
# calcuate packet checksum
sub _checksum {
	my $checksum;
	map {$checksum+=ord} (split //,pop @_);
	sprintf("%X",$checksum%256);
}

###########################################################################################################
# calculate data length
sub _data_len {
	my $len=length(pop @_)+17;
	for (1..(5-length($len))) {
		$len = '0'.$len;
	}
	$len;
}

###########################################################################################################
sub _ia5_encode {
	join('',map {sprintf "%X",ord} split(//,pop(@_)));
