create table netlogon_request (
id integer primary key,
domain text not null,
hostName text not null,
dnsDomain text,
dnsHostName text,
ntVersion text not null
);

create table netlogon_response_info (
id integer primary key autoincrement,
requestId integer references netlogon_request(id) on delete cascade,
responseType text,
exception text
);

create table netlogon_sam_logon_nt40_response (
id integer primary key autoincrement,
requestId integer references netlogon_request(id) on delete cascade,
opcode text not null,
unicodeLogonServer text,
unicodeUserName text,
unicodeDomainName text,
ntVersion text not null
);

create table netlogon_sam_logon_response (
id integer primary key autoincrement,
requestId integer references netlogon_request(id) on delete cascade,
opcode text not null,
unicodeLogonServer text,
unicodeUserName text,
unicodeDomainName text,
domainGuid text not null,
dnsForestName text not null,
dnsDomainName text not null,
dnsHostName text not null,
dcIpAddress text not null,
flags text not null,
ntVersion text not null
);

create table netlogon_sam_logon_ex_response (
id integer primary key autoincrement,
requestId integer references netlogon_request(id) on delete cascade,
opcode text not null,
flags text not null,
domainGuid text not null,
dnsForestName text not null,
dnsDomainName text not null,
dnsHostName text not null,
netbiosDomainName text,
netbiosComputerName text,
userName text,
dcSiteName text not null,
clientSiteName text,
dcSockAddr text,
nextClosestSiteName text,
ntVersion text not null
);
