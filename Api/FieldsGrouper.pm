package Api::FieldsGrouper;

use warnings FATAL => 'all';
use strict;

#***********************************************************
=head2 group_fields()

=cut
#***********************************************************
sub group_fields {
  my ($result) = @_;

  if (ref $result eq 'ARRAY') {
    foreach (@$result) {
      $_ = group($_)
    }
  }
  else {
    $result = group($result)
  }

  return $result;
}

#***********************************************************
=head2 group()

=cut
#***********************************************************
sub group {
  my ($result) = @_;

  my @del_fields_array = (
    '',
    'COL_NAMES_ARR',
    'db',
    'admin',
    'conf',
    'lang',
    'modules',
    'debug',
    'Conf',
    'CONF',
    'Admin',
    'ADMIN',
    'LANG',
    'MODULES',
    'list'
  );

  if (ref $result eq 'HASH') {
    foreach my $field_name (keys %$result) {
      if ($field_name =~ m/(.*)_(\d*)$/gm) {
        delete $result->{$field_name};
      }
      else {
        foreach my $field (@del_fields_array) {
          delete $result->{$field_name} if ($field_name eq $field)
        }
      }

      if ($field_name =~ m/(.*)_ALL$/gm) {
        my $old_field_name = $field_name;
        $field_name =~ s/_ALL$//gm;

        my @list = split(', ', $result->{$old_field_name});
        $result->{$field_name} = \@list;
        delete $result->{$old_field_name};
      }
    }
  }

  return $result;
}

1;
