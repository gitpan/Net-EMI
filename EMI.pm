package Net::EMI;
use strict;
use Carp;
#
# Copyright (c) 2001,2002 and 2003 Jochen Schneider <jochen.schneider@mediaways.net>.
# Copyright (c) 2002 and 2003 Gustav Schaffter.
# All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use vars qw($VERSION);
$VERSION='1.0';

use IO::Socket;

use constant STX=>chr(2);           # start transmission
use constant ETX=>chr(3);           # end transmission
use constant SLASH=>'/';            # ucp delimiter
use constant DEF_SMSC_PORT=>3024;   # Default port.
use constant ACK=>'A';
#use constant NACK=>'N';            # Currently not used.

use constant TRUE=>1;

BEGIN{*logout=*close_link;}

###########################################################################################################
sub new {
   my$self={};
   bless($self,shift())->_init(@_);
}

###########################################################################################################
# login to SMSC
sub login {
   my$self=shift();
   my%args=(
      SMSC_ID=>'',
      SMSC_PW=>'',
      @_);

   # Conditionally open the socket unless already opened.
   $self->open_link() unless(defined($self->{SOCK}));
   unless(defined($self->{SOCK})) {
      return(wantarray?(undef,0,''):undef);
   }

   defined($args{SMSC_ID})&&length($args{SMSC_ID})||do {
      $self->{WARN}&&warn("Missing mandatory parameter 'SMSC_ID' when trying to login. Login failed");
      return(wantarray?(undef,0,''):undef);
   };

   defined($args{SMSC_PW})&&length($args{SMSC_PW})||do {
      $self->{WARN}&&warn("Missing mandatory parameter 'SMSC_PW' when trying to login. Login failed");
      return(wantarray?(undef,0,''):undef);
   };

	my $data=$args{SMSC_ID}. # OAdC
	         SLASH.
	         '6'.     # OTON (short number alias)
	         SLASH.
	         '5'.     # ONPI (private)
	         SLASH.
	         '1'.     # STYP (open session)
	         SLASH.
	         $self->_ia5_encode($args{SMSC_PW}).   # PWD
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
	           '60';                             # OT (Session management).

	my $checksum=$self->_checksum($header.SLASH.$data.SLASH);
	$self->_transmit_msg($header.SLASH.$data.SLASH.$checksum);
}

#############################################################################################
# This method will also conditionally be called from the login() method.
sub open_link {
   my$self=shift;

   $self->{SOCK}=IO::Socket::INET->new(PeerAddr=>$self->{SMSC_HOST},
                                       PeerPort=>$self->{SMSC_PORT},
                                       Proto=>'tcp');
   defined($self->{SOCK})||do {
      # Error handling can and will be improved here.
      $self->{WARN}&&warn("Failed to establish a socket connection with host $self->{SMSC_HOST} on port $self->{SMSC_PORT} ");
      return;
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
   my$self=shift();
   my%args=(
      RECIPIENT=>'',
      MESSAGE_TEXT=>'',
      SENDER_TEXT=>'',
      @_);

   defined($args{RECIPIENT})&&length($args{RECIPIENT})||do {
      $self->{WARN}&&warn("Missing mandatory parameter 'RECIPIENT' when trying to send message. Transmission failed");
      return(wantarray?(undef,0,''):undef);
   };

	$args{RECIPIENT}=~s/^\+/00/;
	$args{RECIPIENT}=~/^\d+$/||do{
	   $self->{WARN}&&warn("The recipient address contains illegal (non-numerical) characters: $args{RECIPIENT}\nMessage not sent ");
      return(wantarray?(undef,0,''):undef);
	};

   # It's OK to send an empty message, but not to use undef.
   defined($args{MESSAGE_TEXT})||($args{MESSAGE_TEXT}='');

	my $data=$args{RECIPIENT}. # AdC (Address Code)
	         SLASH.
	         # OAdC (Originators Adress Code)
	         # If given, use it. Otherwise use the one given to the constructor.
	         (defined($args{SENDER_TEXT})&&length($args{SENDER_TEXT})?
	            $self->_encode_7bit($args{SENDER_TEXT}):
	            $self->_encode_7bit($self->{SENDER_TEXT})).
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
	         $self->_ia5_encode($args{MESSAGE_TEXT}).
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
   my$self=shift();
   my%args=(
      SMSC_HOST=>'',
      SMSC_PORT=>DEF_SMSC_PORT,
      SENDER_TEXT=>'',
      WARN=>0,
      @_);

   $self->{WARN}=defined($args{WARN})?$args{WARN}?1:0:0;

   defined($args{SMSC_HOST})&&length($args{SMSC_HOST})||do{
      $self->{WARN}&&warn("Mandatory entity 'SMSC_HOST' was missing when creating an object of class ".
                          __PACKAGE__.
                          ". Object not created");
      return;       # Failed to instantiate this object.
   };
   defined($args{SMSC_PORT})&&length($args{SMSC_PORT})||do{
      $self->{WARN}&&warn("Mandatory entity 'SMSC_PORT' was missing when creating an object of class ".
                          __PACKAGE__.
                          ". Object not created");
      return;       # Failed to instantiate this object.
   };
   $args{SMSC_PORT}=~/^\d+$/||do{
      $self->{WARN}&&warn("Non-numerical data found in entity 'SMSC_PORT' when creating an object of class ".
                          __PACKAGE__.
                          ". Object not created");
      return;       # Failed to instantiate this object.
   };

   $self->{SMSC_HOST}=$args{SMSC_HOST};
   $self->{SMSC_PORT}=$args{SMSC_PORT};
   $self->{SENDER_TEXT}=defined($args{SENDER_TEXT})&&length($args{SENDER_TEXT})?$args{SENDER_TEXT}:__PACKAGE__;

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
sub _encode_7bit {
   my($self,$msg)=@_;
   my($bits,$ud)=('','');
   my($octet,$foo);

   defined($msg)&&length($msg)||return('');

   for(split(//,$msg)) {
      $bits.=unpack('b7',$_);
   }

   while(defined($bits)&&(length($bits))) {
      $octet=substr($bits,0,8);
      $foo = $octet;
      $ud.=unpack("H2",pack("b8",substr($octet.'0'x7,0,8)));
      $bits=(length($bits)>8)?substr($bits,8):'';
   }

   my$len;
   if(length($foo)<5) {
      $len =sprintf("%02X", (length($ud)-1));
   }
   else {
      $len =sprintf("%02X", length($ud));
   }

   $len.uc($ud);
}

###########################################################################################################
sub _ia5_encode {
	join('',map {sprintf "%X",ord} split(//,pop(@_)));
}

###########################################################################################################
# one step in UCP communication
sub _transmit_msg {
   my($self,$message_string)=@_;
	my($rd,$buffer,$response,$acknack,$errcode,$errtxt,$ack);

	print {$self->{SOCK}} (STX.$message_string.ETX) ||do{
	   $errtxt="Failed to print to SMSC socket. Remote end closed?";
	   $self->{WARN}&&warn($errtxt);
	   wantarray?return(undef,0,$errtxt):return;
   };

	$self->{SOCK}->flush();

	do	{
		$rd=read($self->{SOCK},$buffer,1);
		defined($rd)||do{ # undef, read error.
	      $errtxt="Failed to read from SMSC socket. Never received ETX. Remote end closed?";
	      $self->{WARN}&&warn($errtxt);
	      wantarray?return(undef,0,$errtxt):return;
	   };
		$rd||do{ # Zero, end of 'file'.
	      $errtxt="Never received ETX from SMSC. Remote end closed?";
	      $self->{WARN}&&warn($errtxt);
	      wantarray?return(undef,0,$errtxt):return;
	   };
		$response.=$buffer;
	}	until($buffer eq ETX);

	(undef,undef,undef,undef,$acknack,$errcode,$errtxt,undef)=split(SLASH,$response);
	if($acknack eq ACK) {
	   ($ack,$errcode,$errtxt)=(TRUE,0,'');
	}
	else {
	   $ack=0;
	   $errtxt=~s/^\s+//;
	   $errtxt=~s/\s+$//;
	}
	wantarray?($ack,$errcode,$errtxt):$ack;
}

1;
__END__

=head1 NAME

Net::EMI - EMI/UCP GSM SMSC Protocol Class

=head1 WARNING

=head2 The calling format for the constructor new() plus for the methods login() and send_sms() have changed!

The new format takes a list of named parameters.
Major advantages are that parameters may be given in an arbitrary order, the module may provide certain
default values and that the module developers may add additional parameters and remain backwards compatible.

The drawback is that you must update any of your applications using the Net::EMI.pm module. Sorry.

=head1 SYNOPSIS

C<use Net::EMI>

C<$emi = Net::EMI-E<gt>new(SMSC_HOST=E<gt>'smsc.somedomain.tld', SMSC_PORT=E<gt>3024, SENDER_TEXT=E<gt>'My Self');>

=head1 DESCRIPTION

This module implements a client Interface to the EMI (External Machine Interface) specification,
which itself is based on the ERMES UCP (UNIVERSAL Computer Protocol) with some SMSC-specific
extensions.

The protocol can be used to compose, send, receive, deliver... short messages to GSM Networks via
EMI-enabled SMSC's (Short Message Service Center).
Usually the Network connection is based on TCP/IP or X.25.
The EMI/UCP specification can be found at http://www.cmgtele.com/docs/SMSC_EMI_specification_3.5.pdf .

A new Net::EMI object must be created with the I<new> method. Once
this has been done, all commands are accessed via method calls
on the object.

=head1 EXAMPLE

C<use Net::EMI;>

C<($recipient,$text,$sender)=@ARGV;>

C<my($acknowledge,$error_number,$error_text);>

C<$emi = Net::EMI-E<gt>new(SMSC_HOST=E<gt>'smsc.somedomain.tld', SMSC_PORT=E<gt>3024, SENDER_TEXT=E<gt>'MyApp', WARN=E<gt>1) || die "Failed to create SMSC object";>

C<$emi-E<gt>open_link() || die("Failed to connect to SMSC")>

C<($acknowledge,$error_number,$error_text) = $emi-E<gt>login(SMSC_ID=E<gt>'your_account_id', SMSC_PW=E<gt>'password');>

C<die "Login to SMSC failed. Error nbr: $error_number, Error txt: $error_text\n" unless($acknowledge);>

C<($acknowledge,$error_number,$error_text) = $emi-E<gt>send_sms(RECIPIENT=E<gt>$recipient, MESSAGE_TEXT=E<gt>$text, SENDER_TEXT=E<gt>$sender);>

C<die "Sending SMS failed. Error nbr: $error_number, Error txt: $error_text\n" unless($acknowledge);>


C<$emi-E<gt>close_link();>

=head1 CONSTRUCTOR

=over 4

=item new( SMSC_HOST=>'smsc.somedomain.tld' [, SMSC_PORT=>3024] [, SENDER_TEXT=>'My App'] [, WARN=>1])

The parameters may be given in arbitrary order.

C<SMSC_HOST=E<gt>> B<Mandatory>. The hostname B<or> ip-address of the SMCS.

C<SMSC_PORT=E<gt>> Optional. The TCP/IP port number of your SMSC. If omitted, port number 3024 will be used by default.

C<SENDER_TEXT=E<gt>> Optional. The text that will appear in the receivers mobile phone, identifying you as a sender.
If omitted, the text 'Net::EMI' will be used by default.
You will probably want to provide a more meaningful text than that.

C<WARN=E<gt>> Optional. If this parameter is given and if it evaluates to I<true>,
then any errors will be written to C<STDERR>.
If omitted, or if the parameter evaluates to I<false>, then nothing is written to C<STDERR>.
It is B<strongly> recommended to turn on warnings during the development of an application using the
Net::EMI module. When development is finished, the developer may chose to not require warnings
but to handle all error situations completely in the main application by checking the return values
from Net::EMI.

The constructor returns I<undef> if mandatory information is missing or invalid parameter values are detected.
In this case, the object is discarded (out of scope) by the Perl interpreter and you cannot call any methods on the object handle.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter evaluates to I<true>.

B<Test> the return value from the constructor!

=back

=head1 METHODS

=over 4

=item open_link()

Open the communication link to the SMSC.
In reality, this opens up a socket to the SMSC.
Be aware that this is B<not> an authenticated login but that the login() method must also be called before any SMS messages can be sent to the SMSC.
open_link() is useful since the main application can verify that it's at all possible to communicate with the SMSC.
(Think: getting through a firewall.)

This method takes no parameters, since it will use the parameters from the constructor.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

C<open_link()> returns B<true> on success and B<undef> in case something went wrong.

=item login(SMSC_ID=>'my_account_id', SMSC_PW=>'MySecretPassword')

Authenticates against the SMSC with the given SMSC-id and password.
Operation 60 of EMI Protocol.
If the open_link() method has not explicitly been called by the main application,
the login() method will do it before trying to authenticate with the SMSC.

The parameters may be given in arbitrary order.

C<SMSC_ID=E<gt>> B<Mandatory>. A string which should be a valid account ID at the SMSC.

C<SMSC_PW=E<gt>> B<Mandatory>. A valid password at the SMSC.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

Return values:

In a scalar context, login() will return I<true> for success, I<false> for transmission failure
and I<undef> for application related errors.
Application related errors may be for instance that a mandatory parameter is missing.
All such errors will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

In an array context, login() will return the three values: C<($acknowledge, $error_number, $error_text);>
where C<$acknowledge> holds the same value as when the method is called in scalar context
(i.e. I<true>, I<false> or I<undef>),
C<$error_number> contains a numerical error code from the SMSC and
C<$error_text> contains a (relatively) explanatory text about the error.

Be aware that both C<$error_number> and C<$error_text> are provided in a response from the SMSC,
which means that the data quality of these entities depends on how well the SMSC has implemented the protocol.

If C<$acknowledge> is I<undef>, then C<$error_number> will be set to 0 (zero) and C<$error_text> will
contain a zero length string.

It is B<strongly> recommended to call login() in an array context, since this provides for an improved error handling
in the main application.

=item send_sms( RECIPIENT=>'9999999999' [, MESSAGE_TEXT=>'A Message'] [, SENDER_TEXT=>'Other App'])

Submits the SMS message to the SMSC (Operation 51) and waits for an SMSC acknowledge.

The parameters may be given in arbitrary order.

C<RECIPIENT=E<gt>> B<Mandatory>. This is the phone number of the recipient in international format with leading + or 00.

C<MESSAGE_TEXT=E<gt>> Optional. A text message to be transmitted. It is accepted to transfer an empty message,
so if this parameter is missing, an empty message will be sent.

C<SENDER_TEXT=E<gt>> Optional. The text that will appear in the receivers mobile phone, identifying you as a sender.
This text will B<temporarily> replace the text given to the constructor.
If omitted, the text already given to the constructor will be used.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

Return values:

In a scalar context, send_sms() will return I<true> for success, I<false> for transmission failure
and I<undef> for application related errors.
Application related errors may be for instance that a mandatory parameter is missing.
All such errors will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

In an array context, send_sms() will return the three values: C<($acknowledge, $error_number, $error_text);>
where C<$acknowledge> holds the same value as when the method is called in scalar context
(i.e. I<true>, I<false> or I<undef>),
C<$error_number> contains a numerical error code from the SMSC and
C<$error_text> contains a (relatively) explanatory text about the error.

Be aware that both C<$error_number> and C<$error_text> are provided in a response from the SMSC,
which means that the data quality of these entities depends on how well the SMSC has implemented the protocol.

If C<$acknowledge> is I<undef>, then C<$error_number> will be set to 0 (zero) and C<$error_text> will
contain a zero length string.

It is B<strongly> recommended to call send_sms() in an array context, since this provides for an improved error handling
in the main application.

B<Note!>
The fact that the message was successfully transmitted to the SMSC does B<not>
guarantee immediate delivery to the recipient or in fact any delivery at all.

=item logout()

=item close_link()

logout() is an alias for close_link().
Whichever method name is used, the B<very same code> will be executed.

What goes up, must also come down.
If the main application will continue working on other tasks once the SMS message was sent,
it is possible to explicitly close the communications link to the SMSC with this method.

If the Net::EMI object handle (returned by the new() method) goes out of scope in the main application,
the link will be implicitly closed and in this case it is not necessary to explicitly close the link.

In reality, this method closes the socket established with the SMSC and does some additional house-keeping.
Once the link is closed,
a new call to either open_link() or to login() will try to re-establish the communications link (socket) with the SMSC.

returns nothing (void)

=back

=head1 SEE ALSO

L<IO::Socket>

L<IO::Socket::INET>

=head1 AUTHOR

Jochen Schneider <jochen.schneider@mediaways.net>

=head1 CO-AUTHOR

Gustav Schaffter <schaffter_cpan@hotmail.com>

=head1 COPYRIGHT

Copyright (c) 2001,2002 and 2003 Jochen Schneider.
Copyright (c) 2002 and 2003 Gustav Schaffter.
All rights reserved.
This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

