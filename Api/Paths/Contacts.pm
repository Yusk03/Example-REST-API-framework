package Api::Paths::Contacts;
=head NAME

  Api::Paths::Contacts - Contacts api functions

=cut

use strict;
use warnings FATAL => 'all';

use Contacts;
use Base qw(in_array);

my Contacts $Contacts;

#**********************************************************
=head2 new($db, $conf, $admin, $lang)

=cut
#**********************************************************
sub new {
  my ($class, $db, $admin, $conf, $lang, $debug, $type) = @_;

  my $self = {
    db    => $db,
    admin => $admin,
    conf  => $conf,
    lang  => $lang,
    debug => $debug
  };

  bless($self, $class);

  $Contacts = Contacts->new($self->{db}, $self->{admin}, $self->{conf});

  $self->{routes_list} = ();

  if ($type eq 'user') {
    $self->{routes_list} = $self->user_routes();
  }

  return $self;
}

#**********************************************************
=head2 user_routes() - Returns available API paths

  Returns:
    {
      $resource_1_name => [ # $resource_1_name, $resource_2_name - names of API resources. always equals to first path segment
        {
          method  => 'GET',          # HTTP method. Path can be queried only with this method

          path    => '/users/:uid/', # API path. May contain variables like ':uid'.
                                     # these variables will be passed to handler function as argument ($path_params).
                                     # variables are always numerical.
                                     # example: if route's path is '/users/:uid/', and queried URL
                                     # is '/users/9/', $path_params will be { uid => 9 }.
                                     # if credentials is 'USER', variable :uid will be checked to contain only
                                     # authorized user's UID.

          handler => sub {           # handler function, coderef. Arguments that are passed to handler:
            my (
                $path_params,        # params from path. look at docs of path. hashref.
                $query_params,       # params from query. for details look at Api::Router::new(). hashref.
                                     # keys will be converted from camelCase to UPPER_SNAKE_CASE
                                     # using Base::decamelize unless no_decamelize_params is set
                $module_obj          # object of needed DB module (in this example - Users). used to run it's methods.
                                     # may be empty if name of module is not set.
               ) = @_;

            $module_obj->info(       # handler should return hashref or arrayref with needed data
              $path_params->{uid}
            );                       # in this example we call Users->info, and it's result are implicitly returned
          },

          module  => 'Users',        # name of DB module. it's object will be created and passed to handler as $module_obj. optional.

          type    => 'HASH',         # type of returned data. may be 'HASH' or 'ARRAY'. by default (if not set) it is 'HASH'. optional.

          credentials => [           # arrayref of roles required to use this path. if API user is authorized as at least one of
                                     # these roles access to this path will be granted. optional.
            'ADMIN'                  # may be 'ADMIN' or 'USER'
          ],

          no_decamelize_params => 0, # if set, $query_params for handler will not be converted to UPPER_SNAKE_CASE. optional.

          conf_params => [ ... ]     # variables from $conf to be returned in result. arrayref.
                                     # experimental feature, currently disabled
        },
        ...
      ],
      $resource_2_name => [
        ...
      ],
      ...
    }

=cut
#**********************************************************
sub user_routes {
  my $self = shift;

  return [
    {
      method      => 'DELETE',
      path        => '/user/contacts/:id/',
      handler     => sub {
        my ($path_params, $query_params) = @_;

        my @allowed_types = ();

        push @allowed_types, 5 if ($self->{conf}->{VIBER_TOKEN});
        push @allowed_types, 6 if ($self->{conf}->{TELEGRAM_TOKEN});

        if (!in_array($path_params->{id}, \@allowed_types)) {
          return {
            errno  => 10048,
            errstr => 'Unknown typeId'
          };
        }
        else {
          $Contacts->contacts_del({
            UID     => $path_params->{uid},
            TYPE_ID => $path_params->{id}
          });

          return {
            result => 'Successfully deleted',
          };
        }
      },
      credentials => [
        'USER', 'USERBOT'
      ]
    },
    {
      method      => 'POST',
      path        => '/user/:uid/contacts/push/subscribe/:id/',
      handler     => sub {
        my ($path_params, $query_params) = @_;

        return {
          errstr => 'No field token in body',
          errno  => '5000'
        } if (!$query_params->{TOKEN});

        my $Ureports = '';
        if (in_array('Ureports', \@main::MODULES)) {
          eval {require Ureports; Ureports->import()};
          if (!$@) {
            $Ureports = Ureports->new($self->{db}, $self->{conf}, $self->{admin});
          }
        }

        my $list = $Contacts->push_contacts_list({
          UID     => $path_params->{uid},
          TYPE_ID => $path_params->{id},
          VALUE   => '_SHOW'
        });

        if ($list && !scalar(@{$list})) {
          $Contacts->push_contacts_add({
            TYPE_ID => $path_params->{id},
            VALUE   => $query_params->{TOKEN},
            UID     => $path_params->{uid},
          });

          if ($Ureports) {
            $Ureports->user_send_type_add({
              TYPE        => 10,
              DESTINATION => 1,
              UID         => $path_params->{uid}
            });
          }
        }
        else {
          if ($query_params->{TOKEN} ne $list->[0]->{value}) {
            $Contacts->push_contacts_change({
              ID    => $list->[0]->{id},
              VALUE => $query_params->{TOKEN},
            });

            if ($Ureports) {
              $Ureports->user_send_type_del({
                TYPE => 10,
                UID  => $path_params->{uid}
              });

              $Ureports->user_send_type_add({
                TYPE        => 10,
                DESTINATION => 1,
                UID         => $path_params->{uid}
              });
            }

            return 1;
          }
          else {
            return {
              errstr => 'You are already subscribed',
              errno  => '5001'
            }
          }
        }
      },
      credentials => [
        'USER'
      ]
    },
    {
      method      => 'DELETE',
      path        => '/user/contacts/push/badges/:id/',
      handler     => sub {
        my ($path_params, $query_params) = @_;

        my $list = $Contacts->push_contacts_list({
          UID     => $path_params->{uid},
          TYPE_ID => $path_params->{id},
          VALUE   => '_SHOW'
        });

        if (scalar @$list) {
          $Contacts->push_contacts_change({
            ID     => $list->[0]->{id},
            BADGES => 0,
          });
        }

        return {
          result => 'OK',
        };
      },
      credentials => [
        'USER'
      ]
    },
    {
      method      => 'DELETE',
      path        => '/user/:uid/contacts/push/subscribe/:id/',
      handler     => sub {
        my ($path_params, $query_params) = @_;

        $Contacts->push_contacts_del({
          TYPE_ID => $path_params->{id},
          UID     => $path_params->{uid},
        });

        my $Ureports = '';
        if (in_array('Ureports', \@main::MODULES)) {
          eval {require Ureports; Ureports->import()};
          if (!$@) {
            $Ureports = Ureports->new($self->{db}, $self->{conf}, $self->{admin});
          }
        }

        if ($Ureports) {
          $Ureports->user_send_type_del({
            TYPE => 10,
            UID  => $path_params->{uid}
          });
        }

        return 1;
      },
      module      => 'Contacts',
      credentials => [
        'USER'
      ]
    },
    {
      method      => 'GET',
      path        => '/user/:uid/contacts/push/subscribe/:id/',
      handler     => sub {
        my ($path_params, $query_params) = @_;

        my $list = $Contacts->push_contacts_list({
          UID     => $path_params->{uid},
          TYPE_ID => $path_params->{id},
          VALUE   => '_SHOW'
        });

        delete @{$list->[0]}{qw/type_id id/} if ($list->[0]);

        return $list->[0] || {};
      },
      module      => 'Contacts',
      credentials => [
        'USER', 'USERBOT'
      ]
    },
    {
      method      => 'GET',
      path        => '/user/:uid/contacts/push/messages/',
      handler     => sub {
        my ($path_params, $query_params) = @_;

        my $list = $Contacts->push_messages_list({
          UID     => $path_params->{uid},
          TITLE   => '_SHOW',
          MESSAGE => '_SHOW',
          CREATED => '_SHOW',
          STATUS  => 0,
          TYPE_ID => $query_params->{TYPE_ID} ? $query_params->{TYPE_ID} : '_SHOW',
        });

        return $list || [];
      },
      module      => 'Contacts',
      credentials => [
        'USER', 'USERBOT'
      ]
    },
  ],
}

1;
