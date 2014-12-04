# == Class: wisemapping
#
# Class for configuring wisemapping
#
# http://www.wisemapping.com/
#
# === Parameters
#
# [*version*]
#   Wisemapping version.
#   Default: 3.0.4.
#
# [*user*]
#   User running wisemapping service.
#   Default: wisemapping.
#
# [*group*]
#   Group running wisemapping service.
#   Default: wisemapping.
#
# [*install_dir*]
#   Installation root directory.
#   Default: /opt
#
# [*url_base*]
#   Base URL use to compute downlaod URL.
#   Default: https://bitbucket.org/wisemapping/wisemapping-open-source/downloads
#
# [*db_host*]
#   Host running the database.
#   Default: localhost
#
# [*db_name*]
#   Name of the database.
#   Default: wisemapping
#
# [*db_user*]
#   Username for database connection.
#   Default: wisemapping
#
# [*db_password*]
#   Password for database connection.
#   Default: wisemapping
#
# [*server_send_email*]
#   "from" email account that will appear in the emails sent from the
#   sender.
#   Default: 'root@localhost'
#
# [*support_email*]
#   Support account that the users could use to contact you. This
#   address will appear in emails and in some places in the site.
#   Default: 'root@localhost'
#
# [*error_reporter_email*]
#   Unexpected errors will be reported to this address.
#   Default: ''
#
# [*error_report_email*]
#   Support account that the users could use to contact you. This
#   address will appear in emails and in some places in the site..
#   Default: 'root@localhost'
#
# [*google_recaptcha_enabled*]
#   Enable captcha confirmation.
#   Default: 'true'
#
# [*google_recaptcha_privatekey*]
#   Private ReCaptcha key. See //www.google.com/recaptcha
#   Default: '6LeQ4tISAAAAAMfHMPRKyHupTfA-KE4QeTCnLXhK'
#
# [*google_recaptcha_publickey*]
#   Public ReCaptcha key. See //www.google.com/recaptcha
#   Default: '6LeQ4tISAAAAALzCGKNgRv8UqsDx7Cb0vq4wbJBr'
#
# [*google_analytics_enabled*]
#   Enable Google Analytics.
#   Default: 'false'
#
# [*google_analytics_account*]
#   Google Analytics account
#   Default: 'UA-XXXX'
#
# [*google_ads_enabled*]
#   Enable Google Ads.
#   Default: 'false'
#
# [*admin_user*]
#   Site administration user. This user will have special permissions
#   for operations such as removing users, set password, etc.
#   Default: 'admin@wisemapping.org'
#
# [*security_type*]
#   Two type of security are supported:
#     - db: User are stored in the database. Registration is required in advance.
#     - ldap: Authentication takes place using a LDAP. In this case,
#     security.ldap.* must be configured.
#   Default: 'db'
#
# [*security_ldap_server*]
#   LDAP server to use for authentication.
#   Default: 'ldap://localhost:389'
#
# [*security_ldap_server_user*]
#   Username for the LDAP connection.
#   Default: 'cn=pveiga,dc=wisemapping,dc=com'
#
# [*security_ldap_server_password*]
#   Password for the LDAP connection.
#   Default: 'password'
#
# [*security_ldap_basedn*]
#   Base dn for ldap queries.
#   default: 'dc=wisemapping,dc=com'
#
# [*security_ldap_subdn*]
#   This will be concatenated as part of the DN. In this case, I will be
#   "ou=people". In case this need to be changed, modify the
#   wisemapping-security-ldap.xml
#   default: 'ou=people'
#
# [*security_ldap_auth_attribute*]
#   LDAP Attribute used as authentication login.
#   default: 'mail'
#
# [*security_ldap_lastname_attribute*]
#   LDAP Attribute used as last name.
#   default: 'sn'
#
# [*security_ldap_firstname_attribute*]
#   LDAP Attribute used as first name.
#   default: 'givenName'
#
# [*security_openid_enabled*]
#   Enable OpenId Authentication.
#   default: 'false'
#
# [*documentation_service_basepath*]
#   Url used for REST API documentation
#   default: 'https://${::fqdn}/service'
#
# [*init_script_template*]
#   Template of the init script.
#   Default: wisemapping/wisemapping.init.erb
#
# [*init_script_source*]
#   Name of the file to parse using template() to provide the content of
#   the init script.
#   Default: undef.
#
# [*java_opts*]
#   JAVA_OPTS used in the init script.
#   Default: -Xmx256m.
#
# [*java_home*]
#   If set to a dir, JAVA_HOME will be exported.
#   Default: undef.
#
# === Variables
#
# [*url*]
#   Wisemapping download URL.
#
# [*wisemapping_dir*]
#   Full path to wisemapping installation dir.
#
# === Examples
#
#  include ::wisemapping
#
# Configure parameters using Hiera.
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
  $server_send_email = 'root@localhost',
  $support_email = 'root@localhost',
  $error_reporter_email = '',
  $google_recaptcha_enabled = 'true',
  $google_recaptcha_privatekey = '6LeQ4tISAAAAAMfHMPRKyHupTfA-KE4QeTCnLXhK',
  $google_recaptcha_publickey = '6LeQ4tISAAAAALzCGKNgRv8UqsDx7Cb0vq4wbJBr',
  $google_analytics_enabled = 'false',
  $google_analytics_account = 'UA-XXXX',
  $google_ads_enabled = 'false',
  $admin_user = 'admin@wisemapping.org',
  $security_type = 'db',
  $security_ldap_server = 'ldap://localhost:389',
  $security_ldap_server_user = 'cn=pveiga,dc=wisemapping,dc=com',
  $security_ldap_server_password = 'password',
  $security_ldap_basedn = 'dc=wisemapping,dc=com',
  $security_ldap_subdn = 'ou=people',
  $security_ldap_auth_attribute = 'mail',
  $security_ldap_lastname_attribute = 'sn',
  $security_ldap_firstname_attribute = 'givenName',
  $security_openid_enabled = 'false',
  $documentation_service_basepath = "https://${::fqdn}/service",
  $init_script_template = 'wisemapping/wisemapping.init.erb',
  $init_script_source = undef,
  $java_opts = '-Xmx256m',
  $java_home = undef,
  $ssl = true,
  $ssl_cert = "puppet:///modules/site/certs/${::fqdn}.crt",
  $ssl_key = "puppet:///modules/site/certs/${::fqdn}.key",
) {
  $url = "${url_base}/wisemapping-v${version}.zip"
  $wisemapping_dir = "${install_dir}/wisemapping-v${version}"

  include ::java
  include ::mysql
  include ::nginx

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
      'set database.validation.query "SELECT 1"',
    ],
    notify  => Service['wisemapping'],
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
    ensure     => 'running',
    enable     => true,
    hasrestart => true,
    hasstatus  => true,
    require    => File['/etc/init.d/wisemapping'],
  }

  nginx::resource::upstream { 'wisemapping_app':
    members => [
      'localhost:8080',
      ],
  }
  nginx::resource::vhost { $::fqdn:
    proxy    => 'http://wisemapping_app',
    ssl      => $ssl,
    ssl_cert => $ssl_cert,
    ssl_key  => $ssl_key,
  }

  # Move wisemapping to the ROOT context
  augeas { 'move_wisemapping_to_root_context':
    lens    => 'Xml.lns',
    incl    => "${wisemapping_dir}/contexts/wisemapping.xml",
    changes => [
      'set Configure/Set[#attribute/name=\'contextPath\']/#text /',
    ],
  }

  # Configure Wisemapping using app.properties
  wisemapping::set_property { 'set site_baseurl':
    property     => 'site.baseurl',
    value        => "https://${::fqdn}",
    requirements => [
      Puppi::Netinstall["netinstall_wisemapping_${version}"],
      Augeas['move_wisemapping_to_root_context'],
    ],
  }
  wisemapping::set_property { 'set server_send_email':
    property => 'mail.serverSendEmail',
    value    => $server_send_email,
  }
  wisemapping::set_property { 'set support_email':
    property => 'mail.supportEmail',
    value    => $support_email,
  }
  wisemapping::set_property { 'set error_reporter_email':
    property => 'mail.errorReporterEmail',
    value    => $error_reporter_email,
  }
  wisemapping::set_property { 'set google_recaptcha_enabled':
    property => 'google.recaptcha.enabled',
    value    => $google_recaptcha_enabled,
  }
  wisemapping::set_property { 'set google_recaptcha_privatekey':
    property => 'google.recaptcha.privateKey',
    value    => $google_recaptcha_privatekey,
  }
  wisemapping::set_property { 'set google_recaptcha_publickey':
    property => 'google.recaptcha.publicKey',
    value    => $google_recaptcha_publickey,
  }
  wisemapping::set_property { 'set google_analytics_enabled':
    property => 'google.analytics.enabled',
    value    => $google_analytics_enabled,
  }
  wisemapping::set_property { 'set google_analytics_account':
    property => 'google.analytics.account',
    value    => $google_analytics_account,
  }
  wisemapping::set_property { 'set google_ads_enabled':
    property => 'google.ads.enabled',
    value    => $google_ads_enabled,
  }
  wisemapping::set_property { 'set admin_user':
    property => 'admin.user',
    value    => $admin_user,
  }
  wisemapping::set_property { 'set security_type':
    property => 'security.type',
    value    => $security_type,
  }
  wisemapping::set_property { 'set security_ldap_server':
    property => 'security.ldap.server',
    value    => $security_ldap_server,
  }
  wisemapping::set_property { 'set security_ldap_server_user':
    property => 'security.ldap.server.user',
    value    => $security_ldap_server_user,
  }
  wisemapping::set_property { 'set security_ldap_server_password':
    property => 'security.ldap.server.password',
    value    => $security_ldap_server_password,
  }
  wisemapping::set_property { 'set security_ldap_basedn':
    property => 'security.ldap.basedn',
    value    => $security_ldap_basedn,
  }
  wisemapping::set_property { 'set security_ldap_subdn':
    property => 'security.ldap.subDn',
    value    => $security_ldap_subdn,
  }
  wisemapping::set_property { 'set security_ldap_auth_attribute':
    property => 'security.ldap.auth.attribute',
    value    => $security_ldap_auth_attribute,
  }
  wisemapping::set_property { 'set security_ldap_lastname_attribute':
    property => 'security.ldap.lastName.attribute',
    value    => $security_ldap_lastname_attribute,
  }
  wisemapping::set_property { 'set security_ldap_firstname_attribute':
    property => 'security.ldap.firstName.attribute',
    value    => $security_ldap_firstname_attribute,
  }
  wisemapping::set_property { 'set security_openid_enabled':
    property => 'security.openid.enabled',
    value    => $security_openid_enabled,
  }
  wisemapping::set_property { 'set documentation_service_basepath':
    property => 'documentation.services.basePath',
    value    => $documentation_service_basepath,
  }
}

# vim: set et sta sw=2 ts=2 sts=2 noci noai:
