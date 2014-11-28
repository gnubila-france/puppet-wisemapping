# == Class: wisemapping
#
# Class for configuring wisemapping
#
# http://www.wisemapping.com/
#
# === Examples
#
#  include wisemapping
#
# === Authors
#
# Baptiste Grenier <bgrenier@gnubila.fr>
#
# === Copyright
#
# Copyright 2014 gńubila
#
class wisemapping (
  $version = '3.0.4',
  $user = 'wisemapping',
  $group = 'wisemapping',
  $install_dir = '/opt',
  $url_base = 'https://bitbucket.org/wisemapping/wisemapping-open-source/downloads',
  $db_host = 'localhost',
  $db_name = 'wisemapping',
  $db_user = 'wisemapping',
  $db_password = 'wisemapping',
  $init_script_template = 'wisemapping/wisemapping.init.erb',
  $init_script_source = undef,
) {
  $url = "${url_base}/wisemapping-v${version}.zip"
  $wisemapping_dir = "${install_dir}/wisemapping-v${version}"

  include ::java
  include ::mysql

  $manage_file_source = $wisemapping::init_script_source ? {
    ''        => undef,
    default   => $wisemapping::init_script_source,
  }
  $manage_file_content = $wisemapping::init_script_template ? {
    ''        => undef,
    default   => template($wisemapping::init_script_template),
  }

  # User and group for running the application
  if !defined(Group[$group]) {
    group { $group:
      ensure => 'present',
    }
  }
  if !defined(User[$user]) {
    user { $user:
      ensure   => 'present',
      system   => true,
      gid      => $group,
      home     => '/dev/null',
      password => '*',
    }
  }

  puppi::netinstall { "netinstall_wisemapping_${version}":
    url                 => $url,
    destination_dir     => $install_dir,
    postextract_command => "chmod -R u=rwX,g=rwX,o=-r-w-x ${wisemapping_dir}",
    owner               => $user,
    group               => $group,
    require             => [
      User[$user],
      Group[$group],
    ],
  }

  mysql::grant { "${db_user}@${db_host}-${db_name}":
    mysql_privileges         => 'ALL',
    mysql_password           => $db_password,
    mysql_db                 => $db_name,
    mysql_user               => $db_user,
    mysql_host               => $db_host,
    mysql_db_init_query_file => "${wisemapping_dir}/config/database/mysql/create-schemas.sql",
    require                  => Puppi::Netinstall["netinstall_wisemapping_${version}"],
  }

  # Enable MySQL DB backend instead of default HSQLDB
  augeas { 'setup-mysql-properties':
    lens    => 'Properties.lns',
    incl    => "${wisemapping_dir}/webapps/wisemapping/WEB-INF/app.properties",
    changes => [
      "set database.url jdbc:mysql://${db_host}/${db_name}?useUnicode=yes&characterEncoding=UTF-8",
      'set database.driver com.mysql.jdbc.Driver',
      'set database.hibernate.dialect org.hibernate.dialect.MySQL5Dialect',
      "set database.username ${db_user}",
      "set database.password ${db_password}",
      'set database.validation.enabled true',
      'set database.validation.query SELECT 1',
    ],
    require => [
      Puppi::Netinstall["netinstall_wisemapping_${version}"],
      Mysql::Grant["${db_user}@${db_host}-${db_name}"],
    ],
  }

  file { '/etc/init.d/wisemapping':
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => $wisemapping::manage_file_source,
    content => $wisemapping::manage_file_content,
    require => Puppi::Netinstall["netinstall_wisemapping_${version}"],
  }
  service { 'wisemapping':
    ensure     => 'stopped',
    enable     => false,
    hasrestart => true,
    hasstatus  => true,
    require    => File['/etc/init.d/wisemapping'],
  }
}

# vim: set et sta sw=2 ts=2 sts=2 noci noai: