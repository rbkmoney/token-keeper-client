-module(token_keeper_authority_offline).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

-export([create/4]).
-export([get/2]).
-export([revoke/2]).

-define(APP, token_keeper_client).

%% API types

-type create_error() :: {auth_data, already_exists}.
-type get_error() :: {auth_data, not_found}.
-type revoke_error() :: {auth_data, not_found}.

-export_type([create_error/0]).
-export_type([get_error/0]).
-export_type([revoke_error/0]).

%% Internal types

-type auth_data_id() :: token_keeper_client:auth_data_id().
-type context_fragment() :: token_keeper_client:context_fragment().
-type metadata() :: token_keeper_client:metadata().
-type auth_data() :: token_keeper_client:auth_data().

-type client() :: token_keeper_client:client().
-type result(Ok, Error) :: {ok, Ok} | {error, Error}.

%% API functions

-spec create(auth_data_id(), context_fragment(), metadata(), client()) -> result(auth_data(), create_error()).
create(ID, ContextFragment, Metadata, Client) ->
    Request = make_request('Create', {ID, ContextFragment, Metadata}),
    case call(Request, Client) of
        {ok, AuthData} ->
            {ok, token_keeper_client_codec:decode_authdata(AuthData)};
        {exception, Exception} ->
            {error, map_exception(Exception)}
    end.

-spec get(auth_data_id(), client()) -> result(auth_data(), get_error()).
get(ID, Client) ->
    Request = make_request('Get', {ID}),
    case call(Request, Client) of
        {ok, AuthData} ->
            {ok, token_keeper_client_codec:decode_authdata(AuthData)};
        {exception, Exception} ->
            {error, map_exception(Exception)}
    end.

-spec revoke(auth_data_id(), client()) -> result(ok, revoke_error()).
revoke(ID, Client) ->
    Request = make_request('Revoke', {ID}),
    case call(Request, Client) of
        {ok, ok} ->
            {ok, ok};
        {exception, Exception} ->
            {error, map_exception(Exception)}
    end.

%% Internal functions

make_request(Function, Args) ->
    {get_service_name(), Function, Args}.

get_service_name() ->
    {tk_token_keeper_thrift, 'TokenAuthority'}.

call(Request, #{
    woody_client := WoodyClient,
    woody_context := WoodyContext
}) ->
    token_keeper_client_woody:call(Request, WoodyClient, WoodyContext).

map_exception(#token_keeper_AuthDataAlreadyExists{}) ->
    {auth_data, already_exists};
map_exception(#token_keeper_AuthDataNotFound{}) ->
    {auth_data, not_found}.
