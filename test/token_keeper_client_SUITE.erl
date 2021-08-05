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
    create_ephemeral_ok/1,
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

-define(CTX_FRAGMENT, #bctx_ContextFragment{type = v1_thrift_binary}).
-define(METADATA, #{
    ?USER_SESSION_NS => #{
        <<"user_id">> => ?USER_ID,
        <<"user_email">> => ?USER_EMAIL
    },
    ?API_KEY_NS => #{
        <<"party_id">> => ?PARTY_ID
    }
}).
-define(AUTHORITY, <<"kinginthecastle">>).

-define(AUTHDATA(Token), ?AUTHDATA(Token, ?CTX_FRAGMENT, ?METADATA)).
-define(AUTHDATA(Token, ContextFragment, Metadata), #token_keeper_AuthData{
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
        {group, auth_data_util_tests},
        {group, woody_client_tests}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {service_client_tests, [
            get_by_token_ok,
            create_ephemeral_ok
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
            {service_client, #{
                url => <<"http://token_keeper:8022/">>,
                timeout => ?TIMEOUT,
                retries => #{
                    'GetByToken' => ?RETRY_STRATEGY,
                    'CreateEphemeral' => ?RETRY_STRATEGY,
                    '_' => finish
                }
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

-spec create_ephemeral_ok(config()) -> test_return().
create_ephemeral_ok(C) ->
    mock_token_keeper(
        fun('CreateEphemeral', {ContextFragment, Metadata}) ->
            {ok, ?AUTHDATA(?TOKEN_STRING, ContextFragment, Metadata)}
        end,
        C
    ),
    WoodyContext = woody_context:new(),
    ?assertEqual(
        ?AUTHDATA(?TOKEN_STRING, ?CTX_FRAGMENT, ?METADATA),
        token_keeper_client:create_ephemeral(?CTX_FRAGMENT, ?METADATA, WoodyContext)
    ),
    ok.

-spec get_by_token_ok(config()) -> test_return().
get_by_token_ok(C) ->
    mock_token_keeper(
        fun('GetByToken', {Token, _}) ->
            {ok, ?AUTHDATA(Token)}
        end,
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
    mock_token_keeper(
        fun('GetByToken', {Token, _}) ->
            {ok, ?AUTHDATA(Token)}
        end,
        C
    ),
    WoodyContext = woody_context:new(),
    {ok, AuthData} = token_keeper_client:get_by_token(?TOKEN_STRING, undefined, WoodyContext),
    ?assertEqual(?USER_ID, token_keeper_auth_data:get_metadata(?USER_SESSION_NS, <<"user_id">>, AuthData)),
    ?assertEqual(?USER_EMAIL, token_keeper_auth_data:get_metadata(?USER_SESSION_NS, <<"user_email">>, AuthData)),
    ?assertEqual(?PARTY_ID, token_keeper_auth_data:get_metadata(?API_KEY_NS, <<"party_id">>, AuthData)),
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
    mock_token_keeper(
        fun('GetByToken', {Token, _}) ->
            ok = timer:sleep(5000),
            {ok, ?AUTHDATA(Token)}
        end,
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
-define(HOST_NAME, "localhost").

mock_token_keeper(HandlerFun, SupOrConfig) ->
    ServiceUrl = mock_token_keeper_(HandlerFun, SupOrConfig),
    set_cfg_url(ServiceUrl).

set_cfg_url(ServiceUrl) ->
    {ok, ClientCfg} = application:get_env(?APP, service_client),
    ok = application:set_env(
        ?APP,
        service_client,
        ClientCfg#{url => ServiceUrl}
    ).

mock_token_keeper_(HandlerFun, Config) when is_list(Config) ->
    mock_token_keeper_(HandlerFun, ?config(test_sup, Config));
mock_token_keeper_(HandlerFun, SupPid) when is_pid(SupPid) ->
    {ok, IP} = inet:parse_address(?HOST_IP),
    ServiceName = token_keeper,
    ServerRef = {mock, ServiceName},
    ChildSpec = woody_server:child_spec(
        ServerRef,
        Options = #{
            ip => IP,
            port => 0,
            event_handler => scoper_woody_event_handler,
            handlers => [mock_service_handler(ServiceName, HandlerFun)]
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    {IP, Port} = woody_server:get_addr(ServerRef, Options),
    make_url(ServiceName, Port).

mock_service_handler(ServiceName, HandlerFun) ->
    {make_path(ServiceName), {get_service_modname(ServiceName), {token_keeper_mock, #{function => HandlerFun}}}}.

get_service_modname(token_keeper) ->
    {tk_token_keeper_thrift, 'TokenKeeper'}.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).
