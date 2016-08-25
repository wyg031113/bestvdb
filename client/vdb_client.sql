drop database if exists `vdb_client`;
create database `vdb_client`;
use `vdb_client`;

drop table if exists `vdb_sk`;


create table `vdb_sk`(`id`        INT NOT NULL,
                      `y`         varbinary(128),
                      `T`         varbinary(128)
                     );
