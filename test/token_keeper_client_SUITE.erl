-module(token_keeper_client_SUITE).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-type test_case_name() :: atom().
-type group_name() :: atom().
-type config() :: [{atom(), term()}].
-type test_return() :: _ | no_return().

%%

-export([
    authenticate_ok/1,
    create_ephemeral_ok/1,
    create_ok/1,
    get_ok/1,
    revoke_ok/1,
    not_configured_authority/1,
    follows_retries/1,
    follows_timeout/1
]).

%%

-define(TIMEOUT, 1000).
-define(RETRY_NUM, 3).
-define(RETRY_TIMEOUT, 100).
-define(RETRY_STRATEGY, {linear, ?RETRY_NUM, ?RETRY_TIMEOUT}).

-define(TOKEN_STRING, <<"letmein">>).
-define(USER_ID, <<"TEST_USER">>).
-define(USER_EMAIL, <<"TEST_EMAIL">>).
-define(PARTY_ID, <<"TEST_PARTY">>).

-define(CTX_FRAGMENT, #bctx_ContextFragment{type = v1_thrift_binary}).
-define(METADATA, #{
    <<"user_id">> => ?USER_ID,
    <<"user_email">> => ?USER_EMAIL,
    <<"party_id">> => ?PARTY_ID
}).
-define(AUTHORITY, <<"kinginthecastle">>).

-define(AUTHDATA(Token), ?AUTHDATA(Token, ?CTX_FRAGMENT, ?METADATA)).
-define(AUTHDATA(Token, ContextFragment, Metadata), ?AUTHDATA(undefined, Token, ContextFragment, Metadata)).
-define(AUTHDATA(ID, Token, ContextFragment, Metadata), #token_keeper_AuthData{
    id = ID,
    token = Token,
    status = active,
    context = ContextFragment,
    metadata = Metadata,
    authority = ?AUTHORITY
}).

%%

-spec all() -> [test_case_name() | {group, group_name()}].
all() ->
    [
        {group, service_client_tests},
        {group, woody_client_tests}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {service_client_tests, [], [
            authenticate_ok,
            create_ephemeral_ok,
            create_ok,
            get_ok,
            revoke_ok,
            not_configured_authority
        ]},
        {woody_client_tests, [], [
            follows_retries,
            follows_timeout
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    Apps =
        genlib_app:start_application_with(token_keeper_client, [
            {service_clients, #{
                authenticator => #{
                    url => <<"http://token_keeper:8022/v2/authenticator">>,
                    timeout => ?TIMEOUT,
                    retries => #{
                        'Authenticate' => ?RETRY_STRATEGY,
                        '_' => finish
                    }
                },
                authorities => #{
                    ephemeral => #{
                        ephemeral_authority => #{
                            url => <<"http://token_keeper:8022/v2/authority/ephemeral_authority">>,
                            timeout => ?TIMEOUT,
                            retries => #{
                                'Create' => ?RETRY_STRATEGY,
                                '_' => finish
                            }
                        }
                    },
                    offline => #{
                        offline_authority => #{
                            url => <<"http://token_keeper:8022/v2/authority/offline_authority">>,
                            timeout => ?TIMEOUT,
                            retries => #{
                                'Create' => ?RETRY_STRATEGY,
                                'Get' => ?RETRY_STRATEGY,
                                'Revoke' => ?RETRY_STRATEGY,
                                '_' => finish
                            }
                        }
                    }
                }
            }}
        ]),
    [{apps, Apps}] ++ Config.

-spec end_per_suite(config()) -> _.
end_per_suite(Config) ->
    _ = [application:stop(App) || App <- proplists:get_value(apps, Config)],
    Config.

%%

-spec init_per_group(group_name(), config()) -> config().
init_per_group(_Name, C) ->
    C.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Name, _C) ->
    ok.

%%

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(_Name, C) ->
    [{test_sup, start_mocked_service_sup()} | C].

-spec end_per_testcase(test_case_name(), config()) -> config().
end_per_testcase(_Name, C) ->
    _ = stop_mocked_service_sup(?config(test_sup, C)),
    C.

%%

-spec authenticate_ok(config()) -> test_return().
authenticate_ok(C) ->
    mock_token_keeper(
        [
            {authenticator, fun('Authenticate', {Token, _}) ->
                {ok, ?AUTHDATA(Token)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:authenticator(WoodyContext),
    ?assertEqual(
        {ok, token_keeper_client_codec:decode_authdata(?AUTHDATA(?TOKEN_STRING))},
        token_keeper_authenticator:authenticate(?TOKEN_STRING, #{}, Client)
    ),
    ok.

-spec create_ephemeral_ok(config()) -> test_return().
create_ephemeral_ok(C) ->
    mock_token_keeper(
        [
            {{authority, {ephemeral, ephemeral_authority}}, fun('Create', {ContextFragment, Metadata}) ->
                {ok, ?AUTHDATA(?TOKEN_STRING, ContextFragment, Metadata)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:ephemeral_authority(ephemeral_authority, WoodyContext),
    ?assertEqual(
        {ok,
            token_keeper_client_codec:decode_authdata(
                ?AUTHDATA(?TOKEN_STRING, ?CTX_FRAGMENT, ?METADATA)
            )},
        token_keeper_authority_ephemeral:create(?CTX_FRAGMENT, ?METADATA, Client)
    ),
    ok.

-spec create_ok(config()) -> test_return().
create_ok(C) ->
    AuthdataID = <<"TEST">>,
    mock_token_keeper(
        [
            {{authority, {offline, offline_authority}}, fun('Create', {ID, ContextFragment, Metadata}) ->
                {ok, ?AUTHDATA(ID, ?TOKEN_STRING, ContextFragment, Metadata)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:offline_authority(offline_authority, WoodyContext),
    ?assertEqual(
        {ok,
            token_keeper_client_codec:decode_authdata(
                ?AUTHDATA(AuthdataID, ?TOKEN_STRING, ?CTX_FRAGMENT, ?METADATA)
            )},
        token_keeper_authority_offline:create(AuthdataID, ?CTX_FRAGMENT, ?METADATA, Client)
    ),
    ok.

-spec get_ok(config()) -> test_return().
get_ok(C) ->
    AuthdataID = <<"TEST">>,
    mock_token_keeper(
        [
            {{authority, {offline, offline_authority}}, fun('Get', {ID}) ->
                {ok, ?AUTHDATA(ID, ?TOKEN_STRING, ?CTX_FRAGMENT, ?METADATA)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:offline_authority(offline_authority, WoodyContext),
    ?assertEqual(
        {ok,
            token_keeper_client_codec:decode_authdata(
                ?AUTHDATA(AuthdataID, ?TOKEN_STRING, ?CTX_FRAGMENT, ?METADATA)
            )},
        token_keeper_authority_offline:get(AuthdataID, Client)
    ),
    ok.

-spec revoke_ok(config()) -> test_return().
revoke_ok(C) ->
    AuthdataID = <<"TEST">>,
    mock_token_keeper(
        [
            {{authority, {offline, offline_authority}}, fun('Revoke', {_ID}) ->
                {ok, ok}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:offline_authority(offline_authority, WoodyContext),
    ?assertEqual(
        {ok, ok},
        token_keeper_authority_offline:revoke(AuthdataID, Client)
    ),
    ok.

-spec not_configured_authority(config()) -> test_return().
not_configured_authority(_C) ->
    WoodyContext = woody_context:new(),
    _ =
        try
            token_keeper_client:offline_authority(some_other_authority, WoodyContext)
        catch
            error:Error ->
                ?assertEqual(Error, {misconfiguration, {not_configured, {offline, some_other_authority}}})
        end,
    ok.

%%

-spec follows_retries(config()) -> _.
follows_retries(_C) ->
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:authenticator(WoodyContext),
    T0 = erlang:monotonic_time(millisecond),
    ?assertError(
        {woody_error, {internal, resource_unavailable, _}},
        token_keeper_authenticator:authenticate(?TOKEN_STRING, #{}, Client)
    ),
    T1 = erlang:monotonic_time(millisecond),
    ?assert(T1 - T0 > ?RETRY_NUM * ?RETRY_TIMEOUT),
    ?assert(T1 - T0 < ?RETRY_NUM * ?RETRY_TIMEOUT * 1.5).

-spec follows_timeout(config()) -> _.
follows_timeout(C) ->
    mock_token_keeper(
        [
            {authenticator, fun('Authenticate', {Token, _}) ->
                ok = timer:sleep(5000),
                {ok, ?AUTHDATA(Token)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    Client = token_keeper_client:authenticator(WoodyContext),
    T0 = erlang:monotonic_time(millisecond),
    ?assertError(
        {woody_error, {external, result_unknown, _}},
        token_keeper_authenticator:authenticate(?TOKEN_STRING, #{}, Client)
    ),
    T1 = erlang:monotonic_time(millisecond),
    ?assert(T1 - T0 > ?TIMEOUT),
    ?assert(T1 - T0 < ?TIMEOUT * 1.5).

%%

start_mocked_service_sup() ->
    {ok, SupPid} = genlib_adhoc_supervisor:start_link(#{}, []),
    _ = unlink(SupPid),
    SupPid.

-spec stop_mocked_service_sup(pid()) -> _.
stop_mocked_service_sup(SupPid) ->
    exit(SupPid, shutdown).

-define(APP, token_keeper_client).
-define(HOST_IP, "::").
-define(HOST_NAME, "localhost").

mock_token_keeper(Handlers, Config) when is_list(Config) ->
    mock_token_keeper(Handlers, ?config(test_sup, Config));
mock_token_keeper(Handlers, SupPid) when is_pid(SupPid) ->
    {ok, IP} = inet:parse_address(?HOST_IP),
    ServiceName = token_keeper,
    ServerRef = {mock, ServiceName},
    ChildSpec = woody_server:child_spec(
        ServerRef,
        Options = #{
            ip => IP,
            port => 0,
            event_handler => scoper_woody_event_handler,
            handlers => mock_service_handlers(Handlers)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    {IP, Port} = woody_server:get_addr(ServerRef, Options),
    _ = override_env_urls(IP, Port, Handlers),
    ok.

mock_service_handlers(Handlers) ->
    [mock_service_handler(Handler) || Handler <- Handlers].

mock_service_handler({HandlerName, HandlerFun}) ->
    {get_handler_path(HandlerName), {get_service_modname(HandlerName), {token_keeper_mock, #{function => HandlerFun}}}}.

get_handler_url(HandlerName) ->
    ClientServiceCfg = get_client_service_config(HandlerName),
    maps:get(url, ClientServiceCfg).

get_handler_path(HandlerName) ->
    get_url_path(get_handler_url(HandlerName)).

get_service_modname(authenticator) ->
    {tk_token_keeper_thrift, 'TokenAuthenticator'};
get_service_modname({authority, {ephemeral, _}}) ->
    {tk_token_keeper_thrift, 'EphemeralTokenAuthority'};
get_service_modname({authority, {offline, _}}) ->
    {tk_token_keeper_thrift, 'TokenAuthority'}.

%%

get_url_path(Url) ->
    #{path := Path} = uri_string:parse(Url),
    Path.

override_env_urls(IP, Port, Handlers) ->
    lists:foreach(
        fun({HandlerName, _}) ->
            override_env_handler_url(HandlerName, IP, Port)
        end,
        Handlers
    ).

override_env_handler_url(HandlerName, _IP, Port) ->
    Path = get_handler_path(HandlerName),
    NewUrl = iolist_to_binary(["http://", ?HOST_NAME, ":", integer_to_list(Port), binary_to_list(Path)]),
    set_handler_url(HandlerName, NewUrl).

set_handler_url(HandlerName, NewUrl) ->
    ClientServiceCfg = get_client_service_config(HandlerName),
    set_client_service_config(HandlerName, ClientServiceCfg#{url => NewUrl}).

%%

get_client_service_config(authenticator) ->
    maps:get(authenticator, get_service_clients());
get_client_service_config({authority, {Type, Name}}) ->
    AuthoritiesConfig = maps:get(authorities, get_service_clients()),
    AuthoritiesType = maps:get(Type, AuthoritiesConfig),
    maps:get(Name, AuthoritiesType).

set_client_service_config(authenticator, ServiceConfig) ->
    set_service_clients(maps:put(authenticator, ServiceConfig, get_service_clients()));
set_client_service_config({authority, {Type, Name}}, ServiceConfig) ->
    set_service_clients(genlib_map:deepput([authorities, Type, Name], ServiceConfig, get_service_clients())).

get_service_clients() ->
    {ok, ServiceClients} = application:get_env(?APP, service_clients),
    ServiceClients.

set_service_clients(Value) ->
    application:set_env(?APP, service_clients, Value).
