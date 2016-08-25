drop database if exists `vdb_server`;
create database `vdb_server`;
use `vdb_server`;
drop table if exists `vdb_pk`;
create table `vdb_pk`(  `id`        INT NOT NULL  PRIMARY KEY AUTO_INCREMENT,
                        `ip`        varchar(17),
                        `port`      int,
                        `dbname`    varchar(128),
                        `dbtable`   varchar(128),
                        `dbpassword`varchar(128),
                        `pair_id`   int,
                        `g`         varchar(256),
                        `CR`        varchar(256),
                        `CT`        varchar(256),
                        `Y`         varchar(256),
                        `beinited`  int,
                        `dbsize`    int,
                        `CVerTimes` int,
                        `VerTimes`  int,
                        `VerStatus` int,
                        `VerProg`   int
                       );

drop table if exists `vdb_s`;
create table `vdb_s`(`id`        INT NOT NULL  PRIMARY KEY,
                     `HT`        varchar(256),
                     `CDTm1`     varchar(256),
                     `CUT`       varchar(256),
                     `T`         varchar(256)
                    );

drop table if exists `vdb_pair`;
create table `vdb_pair`( `id`        INT NOT NULL  PRIMARY KEY AUTO_INCREMENT,
                         `pair`      varchar(4096),
                         `n`         int,
                         `hi_path`  varchar(64),
                         `hij_path` varchar(64)
                       );

insert into vdb_pk(ip, port, dbname, dbtable, beinited) values('127.0.0.1', 3306, 'dbtest', 'plain_tb_test', 0);
insert into vdb_pair(pair, n, hi_path, hij_path) values('type a
    q 761846824583642140659137109691511932305970139082111529327435740215322302774607957097746770718272840631736368526656472350593682110214944570589924161426363
    h 1042553439167367155009765265720648718181117218118179590991794911062254283719885725144521660704510821995452
    r 730750862221594424981965739670091261094297337857
    exp2 159
    exp1 135
    sign1 1
    sign0 1', 2000, '2000/hi', '2000/hij');

