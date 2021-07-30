-module(token_keeper_client).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([create_ephemeral/3]).
-export([get_by_token/3]).

%% API types

-type token() :: token_keeper_auth_data:token().
-type source_context() :: #{request_origin := binary()}.

-export_type([token/0]).
-export_type([source_context/0]).

%% API Errors

-type token_error(T) :: {token, T}.
-type auth_data_error(T) :: {auth_data, T}.
-type context_error(T) :: {context, T}.

-type invalid_token_error() :: token_error(invalid).
-type auth_data_not_found_error() :: auth_data_error(not_found).
-type auth_data_revoked_error() :: auth_data_error(revoked).
-type context_creation_error() :: context_error(creation_failed).

-type get_by_token_errors() ::
    invalid_token_error()
    | auth_data_not_found_error()
    | auth_data_revoked_error()
    | context_creation_error().

-export_type([get_by_token_errors/0]).

%% Internal types

-type context_fragment() :: tk_token_keeper_thrift:'ContextFragment'().
-type metadata() :: token_keeper_auth_data:metadata().

-type source_context_thrift() :: tk_token_keeper_thrift:'TokenSourceContext'().

%%
%% API functions
%%

-spec create_ephemeral(context_fragment(), metadata(), woody_context:ctx()) ->
    token_keeper_auth_data:auth_data().
create_ephemeral(ContextFragment, Metadata, WoodyContext) ->
    call_create_ephemeral(ContextFragment, Metadata, WoodyContext).

-spec get_by_token(token(), source_context() | undefined, woody_context:ctx()) ->
    {ok, token_keeper_auth_data:auth_data()} | {error, get_by_token_errors()}.
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

-spec call_create_ephemeral(context_fragment(), metadata(), woody_context:ctx()) ->
    token_keeper_auth_data:auth_data().
call_create_ephemeral(ContextFragment, Metadata, WoodyContext) ->
    {ok, AuthData} = token_keeper_client_woody:call('CreateEphemeral', {ContextFragment, Metadata}, WoodyContext),
    AuthData.

-spec call_get_by_token(token(), source_context_thrift(), woody_context:ctx()) ->
    {ok, token_keeper_auth_data:auth_data()} | {error, get_by_token_errors()}.
call_get_by_token(Token, TokenSourceContext, WoodyContext) ->
    case token_keeper_client_woody:call('GetByToken', {Token, TokenSourceContext}, WoodyContext) of
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
