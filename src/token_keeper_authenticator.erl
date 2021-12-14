-module(token_keeper_authenticator).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

-export([authenticate/3]).

-define(APP, token_keeper_client).

%% API types

-type authenticate_error() ::
    {token, invalid}
    | {auth_data, not_found}
    | {auth_data, revoked}.

-export_type([authenticate_error/0]).

%% Internal types

-type token() :: token_keeper_client:token().
-type token_context() :: token_keeper_client:token_context().
-type auth_data() :: token_keeper_client:auth_data().

-type client() :: token_keeper_client:client().
-type result(Ok, Error) :: {ok, Ok} | {error, Error}.

%% API functions

-spec authenticate(token(), token_context(), client()) -> result(auth_data(), authenticate_error()).
authenticate(Token, TokenContext, Client) ->
    Request = make_request('Authenticate', {Token, token_keeper_client_codec:encode_token_context(TokenContext)}),
    case call(Request, Client) of
        {ok, AuthData} ->
            {ok, token_keeper_client_codec:decode_authdata(AuthData)};
        {exception, Exception} ->
            {error, map_exception(Exception)}
    end.

%% Internal functions

make_request(Function, Args) ->
    {get_service_name(), Function, Args}.

get_service_name() ->
    {tk_token_keeper_thrift, 'TokenAuthenticator'}.

call(Request, #{
    woody_client := WoodyClient,
    woody_context := WoodyContext
}) ->
    token_keeper_client_woody:call(Request, WoodyClient, WoodyContext).

map_exception(#token_keeper_InvalidToken{}) ->
    {token, invalid};
map_exception(#token_keeper_AuthDataNotFound{}) ->
    {auth_data, not_found};
map_exception(#token_keeper_AuthDataRevoked{}) ->
    {auth_data, revoked}.
