# Define allowing to set java properties.
#
# === Parameters
#
# [*file*]
#   Path to property file.
#   Default: "${wisemapping::wisemapping_dir}/webapps/wisemapping/WEB-INF/app.properties"
#
# [*property*]
#   Name of the property.
#   Default: undef
#
# [*notifications*]
#   Resource(s) to notify. Can be an array.
#   Default: Service['wisemapping']
#
# [*requirements*]
#   Resource(s) to require. Can be an array.
#   Default: Puppi::Netinstall["netinstall_wisemapping_${wisemapping::version}"]
#
# [*value*]
#   Value of the property.
#   Default: undef
#
# === Examples
#
#  wisemapping::set_property { 'set site_baseurl':
#    property     => 'site.baseurl',
#    value        => "https://${::fqdn}"
#    requirements => [
#      Puppi::Netinstall["netinstall_wisemapping_${version}"],
#      Augeas['move_wisemapping_to_root_context'],
#    ],
#  }
#
# === Authors
#
# Baptiste Grenier <bgrenier@gnubila.fr>
#
# === Copyright
#
# Copyright 2014 gńubila
#
define wisemapping::set_property (
  $file = "${wisemapping::wisemapping_dir}/webapps/wisemapping/WEB-INF/app.properties",
  $property = undef,
  $value = undef,
  $notifications = Service['wisemapping'],
  $requirements = Puppi::Netinstall["netinstall_wisemapping_${wisemapping::version}"],
) {
  validate_string($file)
  validate_string($property)
  validate_string($value)

  augeas { "set-${file}-${property}":
    lens    => 'Properties.lns',
    incl    => $file,
    changes => [
      "set ${property} '${value}'",
    ],
    notify  => $notifications,
    require => $requirements,
  }
}

# vim: set et sta sw=2 ts=2 sts=2 noci noai:
