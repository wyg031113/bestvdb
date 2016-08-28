drop database if exists `vdb_server`;
create database `vdb_server`;
use `vdb_server`;
drop table if exists `vdb_pk`;
create table `vdb_pk`(  `id`        INT NOT NULL  PRIMARY KEY AUTO_INCREMENT,
                        `ip`        varchar(17),
                        `port`      int,
                        `dbname`    varchar(128),
                        `dbtable`   varchar(128),
                        `dbuser`    varchar(64),
                        `dbpassword`varchar(32),
                        `pair_id`   int,
                        `g`         varchar(256),
                        `CR`        varchar(256),
                        `CT`        varchar(256),
                        `Y`         varchar(256),
                        `beinited`  varchar(64),
                        `dbsize`    int,
                        `CVerTimes` int,
                        `VerTimes`  int,
                        `VerStatus` varchar(64),
                        `VerProg`   int
                       );

drop table if exists `vdb_s`;
create table `vdb_s`(`id`        INT NOT NULL  PRIMARY KEY,
                     `HT`        varchar(256),
                     `CDTm1`     varchar(256),
                     `CUT`       varchar(256),
                     `T`         bigint
                    );

drop table if exists `vdb_pair`;
create table `vdb_pair`( `id`        INT NOT NULL  PRIMARY KEY AUTO_INCREMENT,
                         `pair`      varchar(4096),
                         `n`         int,
                         `hi_path`  varchar(64),
                         `hij_path` varchar(64)
                       );

insert into vdb_pk(ip, port, dbname, dbpassword, dbtable, beinited, pair_id, dbsize, dbuser) values('127.0.0.1', '3306', 'dbtest', 'letmein', 'plain_tb_test', '0', '1', '80', 'root');
insert into vdb_pair(pair, n, hi_path, hij_path) values('type a
q 8271759348360827537961605128334829118037969258033880778258104434191640579300732815676553540169202927799410790894275748167793507041273320638417656026794527
h 11319534836057086522969844942263529993398082712348911098310950829965593669633462513976420508697550581102048
r 730750818665452757176057050065048642452048576511
exp2 159
exp1 110
sign1 1
sign0 -1', 100, '100/hi', '100/hij');

