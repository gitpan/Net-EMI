# Net::EMI.pm
#
# Copyright (c) 2001,2002 Jochen Schneider <jochen.schneider@mediaways.net>.
# All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::EMI;
use IO::Socket;

$VERSION = "0.9.1";

my $stx = chr(2); # start transmission
my $etx = chr(3); # end transmission
my $slash = "/";  # ucp delimiter

my $SMSC_HOST = '';
my $SMSC_PORT = 0;
my $socket;

sub new # constructor
{
	$SMSC_PORT = pop @_;
	$SMSC_HOST = pop @_;
	$socket = IO::Socket::INET->new(PeerAddr => $SMSC_HOST, PeerPort => $SMSC_PORT, Proto => 'tcp') || return undef;
	return bless{}
}

sub ia5_encode
{
	return join '',map {sprintf "%X",ord} split //,pop @_;
}
sub ia5_decode
{
	my $message = pop @_;
	for ($i=0;$i<=length($message);$i+=2)
	{
		$decoded.=chr(hex(substr($message,$i,2)));
	}
	return $decoded;
}
sub data_len # calculate data length
{
	my $len = length(pop @_)+17;
	for (1..(5-length($len)))
	{
		$len = '0'.$len;
	}
	return $len;
}
sub checksum # calcuate packet checksum
{
	my $checksum;
	map {$checksum+=ord} (split //,pop @_);
	return sprintf "%X" ,$checksum%256;
}
sub login # login to SMSC
{
	my $password = pop @_;
	my $OadC = pop @_;
	
	my $OTON = "6"; #short number alias
	my $ONPI = "5"; #private
	my $STYP = "1"; #open session
	my $PWD  = ia5_encode($password);
	my $VERS = '0100';
	
	my $data = $OadC.$slash.$OTON.$slash.$ONPI.$slash.$STYP.$slash.$PWD.$slash.$NPWD.$slash.$VERS.$slash.$LAdC.$slash.$LTON.$slash.$LNPI.$slash.$OPID.$slash.$RES1;
	my $TRN = "00"; # transaction counter
	my $LEN = data_len($data);
	my $type="O"; # Operation
	my $OT = "60";# submit message
	my $header = $TRN.$slash.$LEN.$slash.$type.$slash.$OT;
	my $checksum = checksum($header.$slash.$data.$slash);
	
	my $message_string = $header.$slash.$data.$slash.$checksum;
	return message($message_string);
}
sub send_sms # send the SMS
{
	my $message = pop @_;
	my $AdC  = pop @_;
	$AdC  =~ s/^\+/00/;
	$AdC !~ /\D/ || return undef;
	my $OAdC = "10ED32391DBE87F373";# Adress Code originator
	my $LRAd = "";                  # Last Resort Address
	my $MT   = "3";                 # message type (alphanumeric)
	$message   = ia5_encode($message);
	my $OTOA = "5039";              # Originator Type of Address
	my $NRq  = "";                  # Notfication Request 1
	my $NT   = "";                  # Notification Type 3
	
	my $data = $AdC.$slash.$OAdC.$slash.$AC.$slash.$NRq.$slash.$NAdC.$slash.$NT.$slash.$NPID.$slash.$LRq.$slash.$LRAd.$slash.$LPID.$slash.$DD.$slash.$DDT.$slash.$VP.$slash.$RPID.$slash.$SCTS.$slash.$Dst.$slash.$Rsn.$slash.$DSCTS.$slash.$MT.$slash.$NB.$slash.$message.$slash.$MMS.$slash.$PR.$slash.$DCs.$slash.$MCLs.$slash.$RPI.$slash.$CPg.$slash.$RPLy.$slash.$OTOA.$slash.$HPLMN.$slash.$XSer.$slash.$RES4.$slash.$RES5;
	my $TRN = "01";
	my $type = 'O';
	my $OT = '51'; # submit message
	my $LEN = data_len($data);
	my $header = $TRN.$slash.$LEN.$slash.$type.$slash.$OT;
	my $checksum = checksum($header.$slash.$data.$slash);
	my $message_string = $header.$slash.$data.$slash.$checksum;
	print $message_string."\n";
	return message($message_string);
}
sub message # one step in UCP communication
{
	my $message_string = pop @_;
	my $buffer;
	my $response;
	print $socket $stx.$message_string.$etx;
	$socket->flush();
	do
	{
		read $socket,$buffer,1;
		$response.=$buffer;
	}
	until ($buffer eq $etx);
	print "\n".$response."\n";
	$response =~ /\/R\/\d\d\/A\// || return undef;
	return TRUE;
}
1;
__END__

=head1 NAME

Net::EMI - EMI/UCP GSM SMSC Protocol Class (BETA!!!!)

=head1 SYNOPSIS
	
use Net::EMI
	
$emi = Net::EMI->new('smsc.youdomain.com',$smsc_port);
	
=head1 DESCRIPTION

This module implements a client Interface to the EMI (External Machine Interface) specification,
which itself is based on the ERMES UCP (UNIVERSAL Computer Protocol) with some SMSC-specific
extensions.
It can be used to compose, send, receive, deliver... short messages to GSM Networks via 
EMI-enabled SMSC's (Short Message Service Center).
Usually the Network connection is based on TCP/IP or X.25.
The EMI/UCP specification can be found here http://www.cmgtele.com/docs/SMSC_EMI_specification_3.5.pdf .

A new Net::EMI object must be created with the I<new> method. Once
this has been done, all commands are accessed via method calls
on the object.

=head1 EXAMPLES

use Net::EMI;
($recipient,$text)=@ARGV;

$emi = Net::EMI->new("smsc.yourdomain.com",3024) || die "can't connect\n";
$emi->login("password") || die "login failed\n";
$emi->send_sms($recipient,$text) || die "sending sms failed\n";

=head1 CONSTRUCTOR

=over 4

=item new ( <host>, <port>)

This is the constructor for a new Net::EMI object.
C<host> is the hostname or ip-address of the SMCS and C<port> the TCP/IP port number.
Returns undef if on connection failure.

=back

=head1 METHODS

unless otherwise stated all methods return either a I<true> on success or I<undef>
in case something went wrong.

=over 4 

=item login ( SMSC_ID, PASSWORD )

Authenticates against the SMSC with the given SMSC-id and password.
Operation 60 of EMI Protocol.

=item send_sms ( RECIPIENT, MESSAGE_TEXT )

Submits the SMS to the SMSC (Operation 51) waits for SMSC response.
I<RECIPIENT> is the phone number of the recipient in international with leading + or 00.
Return of the method means, the message was submitted to the network. This does not mean
the immidiate or guaranteed delivery.

=item ia5_encode ( STRING )

Returns the string in IA5 encoded format.
ia5_encode is an internal method of Net::EMI and usually not necessary for SMS composition.

=item ia5_decode ( STRING )

Counterpart of ia5_encode.

=head1 SEE ALSO

L<IO::Socket>

L<IO::Socket::INET>

=head1 AUTHOR

Jochen Schneider <jochen.schneider@mediaways.net>

=head1 COPYRIGHT

Copyright (c) 2001,2002 Jochen Schneider. All rights reserved.
This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
