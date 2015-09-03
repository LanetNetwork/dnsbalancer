CREATE TABLE `rules` (
	`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	`protocol` tinyint(3) unsigned NOT NULL,
	`ip` varchar(46) NOT NULL,
	`mask` varchar(46) NOT NULL,
	`list` varchar(255) NOT NULL,
	`action` varchar(255) NOT NULL,
	`action_parameters` varchar(255) DEFAULT NULL,
	PRIMARY KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8

CREATE TABLE `lists` (
	`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	`name` varchar(255) NOT NULL,
	`regex` varchar(255) NOT NULL,
	PRIMARY KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
