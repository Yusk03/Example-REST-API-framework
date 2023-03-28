package Api::Validations;

use strict;
use warnings FATAL => 'all';

use Exporter;
use parent 'Exporter';

use constant {
  POST_INTERNET_HANGUP => {
    NAS_ID          => {
      required => 1,
      type     => 'integer'
    },
    NAS_PORT_ID     => {
      required => 1
    },
    USER_NAME       => {
      required => 1
    },
    ACCT_SESSION_ID => {
      required => 1
    },
  },
};

our @EXPORT = qw(
  POST_INTERNET_HANGUP
);

our @EXPORT_OK = qw(
  POST_INTERNET_HANGUP
);

1;
