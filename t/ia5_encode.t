#!/usr/bin/env perl -w
use strict;
use Test;
BEGIN { plan tests => 1 }

use Net::EMI;

ok('7468697320697320736F6D652073656E73656C6573732074657874',Net::EMI::ia5_encode('this is some senseless text'));
exit;
__END__

