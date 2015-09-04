CREATE TABLE `lists` (
	`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	`name` varchar(255) NOT NULL,
	PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `items` (
	`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	`list` bigint(20) unsigned NOT NULL,
	`value` varchar(255) NOT NULL,
	PRIMARY KEY (`id`),
	KEY `list_index` (`list`),
	CONSTRAINT `items_ibfk_1` FOREIGN KEY (`list`) REFERENCES `lists` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `rules` (
	`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	`protocol` tinyint(3) unsigned NOT NULL,
	`ip` varchar(46) NOT NULL,
	`mask` varchar(46) NOT NULL,
	`matcher` varchar(255) NOT NULL,
	`list` bigint(20) unsigned NOT NULL,
	`action` varchar(255) NOT NULL,
	`action_parameters` varchar(255) DEFAULT NULL,
	PRIMARY KEY (`id`),
	KEY `list_index` (`list`),
	CONSTRAINT `rules_ibfk_1` FOREIGN KEY (`list`) REFERENCES `lists` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
