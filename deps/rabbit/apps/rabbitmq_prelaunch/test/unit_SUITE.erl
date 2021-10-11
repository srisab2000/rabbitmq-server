%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2021 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(unit_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).


all() ->
    [
        {group, parallel_tests}
    ].

groups() ->
    [
        {parallel_tests, [parallel], [
            inet_tls_enabled,
            osiris_replication_over_tls_configuration
        ]}
    ].

init_per_group(_, Config) -> Config.
end_per_group(_, Config) -> Config.

init_per_testcase(_, Config) -> Config.

end_per_testcase(_, Config) -> Config.

inet_tls_enabled(_) ->
    InitArgs = init:get_arguments(),
    ?assert(rabbit_prelaunch_conf:inet_tls_enabled(InitArgs ++ [{proto_dist,["inet_tls"]}])),
    ?assertNot(rabbit_prelaunch_conf:inet_tls_enabled(InitArgs)),
    ok.

osiris_replication_over_tls_configuration(Config) ->
    FileOk = ?config(data_dir, Config) ++ "inter_node_tls_ok.config",
    InitArgsOk = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_optfile,[FileOk]}
    ],
    ?assertEqual([
        {osiris, [
            {replication_transport,ssl},
            {replication_server_ssl_options, [
                {cacertfile,"/etc/rabbitmq/ca_certificate.pem"},
                {certfile,"/etc/rabbitmq/server_certificate.pem"},
                {keyfile,"/etc/rabbitmq/server_key.pem"},
                {secure_renegotiate,true},
                {verify,verify_peer},
                {fail_if_no_peer_cert,true}
            ]},
            {replication_client_ssl_options, [
                {cacertfile,"/etc/rabbitmq/ca_certificate.pem"},
                {certfile,"/etc/rabbitmq/client_certificate.pem"},
                {keyfile,"/etc/rabbitmq/client_key.pem"},
                {secure_renegotiate,true},
                {verify,verify_peer},
                {fail_if_no_peer_cert,true}
            ]}
        ]}
    ], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgsOk)),

    FileBroken = ?config(data_dir, Config) ++ "inter_node_tls_broken.config",
    InitArgsBroken = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_optfile,[FileBroken]}
    ],
    ?assertEqual([], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgsBroken)),

    FileNotFound = ?config(data_dir, Config) ++ "inter_node_tls_not_found.config",
    InitArgsNotFound = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_optfile,[FileNotFound]}
    ],
    ?assertEqual([], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgsNotFound)),

    ok.

