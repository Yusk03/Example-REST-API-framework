package Api::Handler;

use strict;
use warnings FATAL => 'all';

use feature 'switch';
no warnings qw(experimental::smartmatch);

use Encode qw(decode_utf8);
use JSON qw(decode_json);

use Contacts;
use Api::FieldsGrouper;
use Base qw(escape_for_sql camelize decamelize in_array check_ip);

#**********************************************************
=head2 new($db, $admin, $conf)

=cut
#**********************************************************
sub new {
  my ($class, $db, $admin, $conf) = @_;

  my $self = {
    db    => $db,
    admin => $admin,
    conf  => $conf,
  };

  bless($self, $class);

  return $self;
}

#**********************************************************
=head2 handler($db, $admin, $conf)

=cut
#**********************************************************
sub handler {
  my $self = shift;
  my ($router, $path) = @_;

  if (!$self->{conf}->{API_ENABLE}) {
    return ({ errstr => 'API didn\'t enable please enable API in config $conf{API_ENABLE}=1;', errno => 301 }, 400);
  }

  my $allowed = $self->check_credentials($router, $path);

  #TODO add admin paths credential
  if ($path->{credentials}) {
    if (in_array('USER', $path->{credentials})) {
      if (!$allowed) {
        return ({ errstr => 'Access denied', errno => 10 }, 401);
      }
    }
    else {
      return ({ errstr => 'Access denied', errno => 10 }, 403);
    }
  }

  my $body = {};
  if ($path->{method} eq 'GET' || $path->{method} eq 'DELETE') {
    $body = $router->req->query_params->to_hash;
  }
  else {
    $body = eval {decode_json($router->req->content->asset->{content});};
  }

  if ($@) {
    return ({ errno => 1, errstr => 'There was an error parsing the body' }, 400);
  }
  $body = escape_for_sql($body);
  $body = $self->decamelize_body($body);

  my $module_obj;
  if ($path->{module}) {
    if ($path->{module} !~ /^[a-zA-Z0-9_:]+$/) {
      return ({ errstr => 'Module is not found', errno => 3 }, 400);
    }

    eval "use $path->{module}";

    if ($@ || !$path->{module}->can('new')) {
      return $router->render(json => { errstr => 'Module is not found', errno => 4 }, 400);
    }

    $module_obj = $path->{module}->new($self->{db}, $self->{admin}, $self->{conf});
  }

  my %params_list = ();
  my (@params) = $path->{path} =~ /(?<=\/:)([\w]+)(?=\/)/g;
  foreach my $param (@params) {
    $params_list{$param} = $router->param($param);
  }

  my $result = '';

  eval {
    $result = $path->{handler}->(
      \%params_list,
      $body,
      $module_obj
    );
  };

  if ($@) {
    return ({ errstr => 'Unknown error, please try later', errno => 20 }, 502);
  }
  elsif ($module_obj->{errno}) {
    return ({ errno => $module_obj->{errno}, errstr => $module_obj->{errstr} }, 400);
  }

  my $response;
  if (ref $result ne 'HASH' && ref $result ne 'ARRAY' && ref $result ne '') {
    foreach my $key (keys %{$result}) {
      $response->{$key} = $result->{$key};
    }
  }
  else {
    $response = $result;

    unless (defined($response)) {
      $response = {};
    }

    unless (ref $response) {
      $response = { result => $response ? 'OK' : 'BAD' }
    }
  }

  $response = Api::FieldsGrouper::group_fields($response);

  return ($response, 200);
}

#**********************************************************
=head2 transform_response($response) - decode utf-8 params and camelize keys

  Arguments:
     $response

  Returns:
    $converted_response

  Function for native json_former of MOJO, not used by now

=cut
#**********************************************************
sub transform_response {
  my $self = shift;
  my ($response, $attr) = @_;
  if (ref $response eq 'ARRAY') {
    for my $i (0 .. $#{$response}) {
      $response->[$i] = $self->transform_response($response->[$i], { ARRAY => 1 });
    }
    return $response;
  }
  elsif (ref $response eq 'HASH') {
    foreach my $key (sort keys %{$response}) {
      my $new_key = camelize($key);
      if ($new_key ne $key) {
        $response->{$new_key} = $response->{$key};
        delete $response->{$key};
      }
      $response->{$new_key} = $self->transform_response($response->{$new_key});
    }
    return $response;
  }
  else {
    # define bool values in response
    if ($response && $response =~ /^(true|false|null)$/) {
      given ($response) {
        when ('true') {return \1;}
        when ('false') {return \0;}
        default {return undef;}
      }
    }
    else {
      $response = camelize($response) if ($response && $attr->{ARRAY});
      $response = decode_utf8($response) if ($response && $response !~ /^[+-]?\d*\.?\d+$/gm);

      return defined($response) ? $response : '';
    }
  }
}

#**********************************************************
=head2 decamelize_body($body) - decamelize keys of request body

  Arguments:
     $body

  Returns:
    $converted_body

=cut
#**********************************************************
sub decamelize_body {
  my $self = shift;
  my ($body) = @_;
  if (ref $body eq 'ARRAY') {
    for my $i (0 .. $#{$body}) {
      $body->[$i] = $self->decamelize_body($body->[$i]);
    }
    return $body;
  }
  elsif (ref $body eq 'HASH') {
    foreach my $key (sort keys %{$body}) {
      my $new_key = decamelize($key);
      $body->{$new_key} = $body->{$key};
      $body->{$new_key} = $self->decamelize_body($body->{$new_key});
    }
    return $body;
  }
  else {
    return defined($body) ? $body : '';
  }
}

#**********************************************************
=head2 check_credentials($router) - Returns status of SID

  Arguments:
    $router - Mojolicious::Lite req/res body object by default in Mojo $c
    $path   - path object. You can read more about it in Api::Paths::list() POD code before function.

  Returns:
    1 - allowed
    0 - not allowed

=cut
#**********************************************************
sub check_credentials {
  my $self = shift;
  my ($router, $path) = @_;

  if (in_array('USER', $path->{credentials}) && $router->req->headers->header('USERSID')) {
    my $uid = $router->param('uid');
    my $sid = $router->req->headers->header('USERSID');
    my ($uid_sign) = ::auth_user('', '', $sid);

    return $uid_sign ne $uid ? 0 : 1;
  }
  elsif ($self->{conf}->{BOT_APIS} && $ENV{REMOTE_ADDR} && check_ip($ENV{REMOTE_ADDR}, $self->{conf}->{BOT_APIS}) &&
    in_array('USERBOT', $path->{credentials}) && $router->req->headers->header('USERBOT'))
  {
    return 0 if (!$router->req->headers->header('USERBOT') || !$router->req->headers->header('USERID'));

    if ($self->{conf}->{BOT_SECRET}) {
      return 0 if (!$router->req->headers->header('BOTSECRET'));
      my $signature = Digest::SHA::sha256_hex($self->{conf}->{BOT_SECRET});
      return 0 if ($signature ne $router->req->headers->header('BOTSECRET'));
    }

    my %bot_types = (
      VIBER    => 5,
      TELEGRAM => 6
    );

    my $Bot_type = $bot_types{$router->req->headers->header('USERBOT')} || '--';
    my $Bot_user = $router->req->headers->header('USERID') || '--';

    my $Contacts = Contacts->new($self->{db}, $self->{admin}, $self->{conf});
    my $list = $Contacts->contacts_list({
      TYPE  => $Bot_type,
      VALUE => $Bot_user,
      UID   => '_SHOW',
    });

    if ($Contacts->{TOTAL} < 1) {
      return 0
    }
    else {
      $router->param('uid') = $list->[0]->{uid};
      return 1;
    }
  }

  return 0;
}

1;
