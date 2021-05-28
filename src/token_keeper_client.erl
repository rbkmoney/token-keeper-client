-module(token_keeper_client).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([get_by_token/3]).

%% API types

-type token() :: binary().
-type source_context() :: #{request_origin := binary()}.

-export_type([token/0]).
-export_type([source_context/0]).

%% Internal types

-type source_context_thrift() :: tk_token_keeper_thrift:'TokenSourceContext'().

%%
%% API functions
%%

-spec get_by_token(token(), source_context() | undefined, woody_context:ctx()) ->
    {ok, tk_auth_data:auth_data()} | {error, _Reason}.
get_by_token(TokenString, SourceContext, WoodyContext) ->
    call_get_by_token(TokenString, encode_source_context(SourceContext), WoodyContext).

%%
%% Internal functions
%%

-spec encode_source_context(source_context() | undefined) -> source_context_thrift().
encode_source_context(#{request_origin := Origin}) ->
    #token_keeper_TokenSourceContext{request_origin = Origin};
encode_source_context(undefined) ->
    #token_keeper_TokenSourceContext{}.

%%

-spec call_get_by_token(token(), source_context_thrift(), woody_context:ctx()) ->
    {ok, tk_auth_data:auth_data()}
    | {error, {token, invalid} | {auth_data, not_found | revoked} | {context, creation_failed}}.
call_get_by_token(Token, TokenSourceContext, WoodyContext) ->
    case tk_client_woody:call('GetByToken', {Token, TokenSourceContext}, WoodyContext) of
        {ok, AuthData} ->
            {ok, AuthData};
        {exception, #token_keeper_InvalidToken{}} ->
            {error, {token, invalid}};
        {exception, #token_keeper_AuthDataNotFound{}} ->
            {error, {auth_data, not_found}};
        {exception, #token_keeper_AuthDataRevoked{}} ->
            {error, {auth_data, revoked}};
        {exception, #token_keeper_ContextCreationFailed{}} ->
            {error, {context, creation_failed}}
    end.
