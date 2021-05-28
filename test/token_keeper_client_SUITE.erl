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
    get_by_token_ok/1,
    get_user_metadata_ok/1,
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

-define(USER_SESSION_NS, <<"test.rbkmoney.usersession">>).
-define(API_KEY_NS, <<"test.rbkmoney.apikey">>).

-define(AUTHDATA(Token), #token_keeper_AuthData{
    token = Token,
    status = active,
    context = #bctx_ContextFragment{type = v1_thrift_binary},
    metadata = #{
        ?USER_SESSION_NS => #{
            <<"user_id">> => ?USER_ID,
            <<"user_email">> => ?USER_EMAIL
        },
        ?API_KEY_NS => #{
            <<"party_id">> => ?PARTY_ID
        }
    },
    authority = <<"kinginthecastle">>
}).

%%

-spec all() -> [test_case_name() | {group, group_name()}].
all() ->
    [
        {group, service_client_tests},
        {group, auth_data_util_tests},
        {group, woody_client_tests}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {service_client_tests, [
            get_by_token_ok
        ]},
        {auth_data_util_tests, [
            get_user_metadata_ok
        ]},
        {woody_client_tests, [
            follows_retries,
            follows_timeout
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    Apps =
        genlib_app:start_application_with(token_keeper_client, [
            {service_clients, #{
                token_keeper => #{
                    url => <<"http://token_keeper:8022/">>,
                    timeout => ?TIMEOUT,
                    retries => #{
                        'GetByToken' => ?RETRY_STRATEGY,
                        '_' => finish
                    }
                }
            }},
            {namespace_mappings, #{
                user_session => ?USER_SESSION_NS,
                api_key => ?API_KEY_NS
            }}
        ]),
    [{apps, Apps}] ++ Config.

-spec end_per_suite(config()) -> _.
end_per_suite(Config) ->
    [application:stop(App) || App <- proplists:get_value(apps, Config)],
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
    stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%

-spec get_by_token_ok(config()) -> test_return().
get_by_token_ok(C) ->
    mock_services(
        [
            {token_keeper, fun('GetByToken', {Token, _}) ->
                {ok, ?AUTHDATA(Token)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    ?assertEqual(
        {ok, ?AUTHDATA(?TOKEN_STRING)},
        token_keeper_client:get_by_token(?TOKEN_STRING, undefined, WoodyContext)
    ),
    ok.

%%

-spec get_user_metadata_ok(config()) -> test_return().
get_user_metadata_ok(C) ->
    mock_services(
        [
            {token_keeper, fun('GetByToken', {Token, _}) ->
                {ok, ?AUTHDATA(Token)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    {ok, AuthData} = token_keeper_client:get_by_token(?TOKEN_STRING, undefined, WoodyContext),
    ?assertEqual(?USER_ID, tk_auth_data:get_user_id(AuthData)),
    ?assertEqual(?USER_EMAIL, tk_auth_data:get_user_email(AuthData)),
    ?assertEqual(?PARTY_ID, tk_auth_data:get_party_id(AuthData)),
    ok.

%%

-spec follows_retries(config()) -> _.
follows_retries(_C) ->
    WoodyContext = woody_context:new(),
    T0 = erlang:monotonic_time(millisecond),
    ?assertError(
        {woody_error, {internal, resource_unavailable, _}},
        token_keeper_client:get_by_token(?TOKEN_STRING, undefined, WoodyContext)
    ),
    T1 = erlang:monotonic_time(millisecond),
    ?assert(T1 - T0 > ?RETRY_NUM * ?RETRY_TIMEOUT),
    ?assert(T1 - T0 < ?RETRY_NUM * ?RETRY_TIMEOUT * 1.5).

-spec follows_timeout(config()) -> _.
follows_timeout(C) ->
    mock_services(
        [
            {token_keeper, fun('GetByToken', {Token, _}) ->
                ok = timer:sleep(5000),
                {ok, ?AUTHDATA(Token)}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    T0 = erlang:monotonic_time(millisecond),
    ?assertError(
        {woody_error, {external, result_unknown, _}},
        token_keeper_client:get_by_token(?TOKEN_STRING, undefined, WoodyContext)
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
-define(HOST_PORT, 8080).
-define(HOST_NAME, "localhost").
-define(HOST_URL, ?HOST_NAME ++ ":" ++ integer_to_list(?HOST_PORT)).

mock_services(Services, SupOrConfig) ->
    maps:map(fun set_cfg/2, mock_services_(Services, SupOrConfig)).

set_cfg(Service, Url) ->
    {ok, Clients} = application:get_env(?APP, service_clients),
    #{Service := BouncerCfg} = Clients,
    ok = application:set_env(
        ?APP,
        service_clients,
        Clients#{Service => BouncerCfg#{url => Url}}
    ).

mock_services_(Services, Config) when is_list(Config) ->
    mock_services_(Services, ?config(test_sup, Config));
mock_services_(Services, SupPid) when is_pid(SupPid) ->
    ServerRef = {dummy, lists:map(fun get_service_name/1, Services)},
    {ok, IP} = inet:parse_address(?HOST_IP),
    ChildSpec = woody_server:child_spec(
        ServerRef,
        Options = #{
            ip => IP,
            port => 0,
            event_handler => scoper_woody_event_handler,
            handlers => lists:map(fun mock_service_handler/1, Services)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    {IP, Port} = woody_server:get_addr(ServerRef, Options),
    lists:foldl(
        fun(Service, Acc) ->
            ServiceName = get_service_name(Service),
            Acc#{ServiceName => make_url(ServiceName, Port)}
        end,
        #{},
        Services
    ).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {token_keeper_mock, #{function => Fun}}}}.

get_service_modname(token_keeper) ->
    {tk_token_keeper_thrift, 'TokenKeeper'}.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).
