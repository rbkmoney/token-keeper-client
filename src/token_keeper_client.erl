-module(token_keeper_client).

-export([authenticator/1]).
-export([ephemeral_authority/2]).
-export([offline_authority/2]).

%% API types

-type token() :: binary().
-type token_context() :: #{
    request_origin => binary()
}.

-type auth_data_id() :: binary().
-type status() :: active | revoked.
-type context_fragment() :: tk_context_thrift:'ContextFragment'().
-type authority_id() :: binary().
-type metadata() :: #{binary() => binary()}.

-type auth_data() :: #{
    id => auth_data_id(),
    token := token(),
    status := status(),
    context := context_fragment(),
    authority => authority_id(),
    metadata => metadata()
}.

-type client() :: #{
    woody_client := woody_client(),
    woody_context := woody_context()
}.

-export_type([token/0]).
-export_type([token_context/0]).

-export_type([auth_data_id/0]).
-export_type([status/0]).
-export_type([context_fragment/0]).
-export_type([authority_id/0]).
-export_type([metadata/0]).

-export_type([auth_data/0]).

-export_type([client/0]).

%% Internal types

-type authority_name() :: atom().

-type woody_client() :: #{
    url := woody:url(),
    timeout => non_neg_integer(),
    retries => #{woody:func() | '_' => genlib_retry:strategy()}
}.

-type woody_context() :: woody_context:ctx().

%% API functions

-spec authenticator(woody_context()) -> client() | no_return().
authenticator(WoodyContext) ->
    make_client(get_authenticator_service_client(), WoodyContext).

-spec ephemeral_authority(authority_name(), woody_context()) -> client() | no_return().
ephemeral_authority(AuthorityName, WoodyContext) ->
    make_client(get_authority_service_client(ephemeral, AuthorityName), WoodyContext).

-spec offline_authority(authority_name(), woody_context()) -> client() | no_return().
offline_authority(AuthorityName, WoodyContext) ->
    make_client(get_authority_service_client(offline, AuthorityName), WoodyContext).

%% Internal functions

make_client(WoodyClient, WoodyContext) ->
    #{
        woody_client => WoodyClient,
        woody_context => WoodyContext
    }.

get_authenticator_service_client() ->
    case maps:get(authenticator, get_service_clients(), #{}) of
        #{} = AuthenticatorConf ->
            AuthenticatorConf;
        undefined ->
            error({misconfiguration, {not_configured, authenticator}})
    end.

get_authority_service_client(Type, Name) ->
    Authoritites = maps:get(authorities, get_service_clients(), #{}),
    AuthorityType = maps:get(Type, Authoritites, #{}),
    case maps:get(Name, AuthorityType, undefined) of
        #{} = AuthorityConf ->
            AuthorityConf;
        undefined ->
            error({misconfiguration, {not_configured, {Type, Name}}})
    end.

get_service_clients() ->
    genlib_app:env(?MODULE, service_clients, #{}).
