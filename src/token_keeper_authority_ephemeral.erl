-module(token_keeper_authority_ephemeral).

-export([create/3]).

-define(APP, token_keeper_client).

%% API types

-type create_error() ::
    {token, invalid}
    | {auth_data, not_found}
    | {auth_data, revoked}.

-export_type([create_error/0]).

%% Internal types

-type context_fragment() :: token_keeper_client:context_fragment().
-type metadata() :: token_keeper_client:metadata().
-type auth_data() :: token_keeper_client:auth_data().

-type client() :: token_keeper_client:client().

%% API functions

-spec create(context_fragment(), metadata(), client()) -> {ok, auth_data()}.
create(ContextFragment, Metadata, Client) ->
    Request = make_request('Create', {ContextFragment, Metadata}),
    {ok, AuthData} = call(Request, Client),
    {ok, token_keeper_client_codec:decode_authdata(AuthData)}.

%% Internal functions

make_request(Function, Args) ->
    {get_service_name(), Function, Args}.

get_service_name() ->
    {tk_token_keeper_thrift, 'EphemeralTokenAuthority'}.

call(Request, #{
    woody_client := WoodyClient,
    woody_context := WoodyContext
}) ->
    token_keeper_client_woody:call(Request, WoodyClient, WoodyContext).
