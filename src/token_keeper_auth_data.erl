-module(token_keeper_auth_data).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([get_id/1]).
-export([get_token/1]).
-export([get_status/1]).
-export([get_context_fragment/1]).
-export([get_metadata/1]).
-export([get_authority/1]).

-export([get_metadata/2]).
-export([get_user_id/1]).
-export([get_user_email/1]).
-export([get_party_id/1]).

%% API types

-type auth_data() :: tk_token_keeper_thrift:'AuthData'().

-type id() :: tk_token_keeper_thrift:'AuthDataID'().
-type token() :: tk_token_keeper_thrift:'Token'().
-type status() :: tk_token_keeper_thrift:'AuthDataStatus'().
-type encoded_fragment() :: {encoded_fragment, tk_token_keeper_thrift:'ContextFragment'()}.
-type metadata() :: #{metadata_ns() => metadata_content()}.
-type metadata_ns() :: tk_token_keeper_thrift:'MetadataNamespace'().
-type metadata_content() :: #{binary() => binary()}.
-type authority() :: tk_token_keeper_thrift:'Authority'().

-export_type([auth_data/0]).
-export_type([id/0]).
-export_type([token/0]).
-export_type([status/0]).
-export_type([encoded_fragment/0]).
-export_type([metadata/0]).
-export_type([metadata_ns/0]).
-export_type([metadata_content/0]).
-export_type([authority/0]).

%%

-define(APP, token_keeper_client).

%%
%% API functions
%%

-spec get_id(auth_data()) -> id() | undefined.
get_id(#token_keeper_AuthData{id = Id}) ->
    Id.

-spec get_token(auth_data()) -> token().
get_token(#token_keeper_AuthData{token = Token}) ->
    Token.

-spec get_status(auth_data()) -> status().
get_status(#token_keeper_AuthData{status = Status}) ->
    Status.

-spec get_context_fragment(auth_data()) -> encoded_fragment().
get_context_fragment(#token_keeper_AuthData{context = Context}) ->
    {encoded_fragment, Context}.

-spec get_metadata(auth_data()) -> metadata().
get_metadata(#token_keeper_AuthData{metadata = Metadata}) ->
    Metadata.

-spec get_authority(auth_data()) -> authority().
get_authority(#token_keeper_AuthData{authority = Authority}) ->
    Authority.

%%

-spec get_metadata(metadata_ns(), auth_data()) -> metadata_content() | undefined.
get_metadata(MetadataNS, #token_keeper_AuthData{metadata = Metadata}) ->
    maps:get(MetadataNS, Metadata, undefined).

-spec get_user_id(auth_data()) -> binary() | undefined.
get_user_id(AuthData) ->
    get_subject_data(<<"user_id">>, get_meta_namespace_user_session(), AuthData).

-spec get_user_email(auth_data()) -> binary() | undefined.
get_user_email(AuthData) ->
    get_subject_data(<<"user_email">>, get_meta_namespace_user_session(), AuthData).

-spec get_party_id(auth_data()) -> binary() | undefined.
get_party_id(AuthData) ->
    get_subject_data(<<"party_id">>, get_meta_namespace_api_key(), AuthData).

%%
%% Internal functions
%%

get_meta_namespace_user_session() ->
    maps:get(user_session, get_meta_ns_conf()).

get_meta_namespace_api_key() ->
    maps:get(api_key, get_meta_ns_conf()).

get_meta_ns_conf() ->
    genlib_app:env(?APP, namespace_mappings, #{}).

get_subject_data(Field, Namespace, AuthData) ->
    case get_metadata(Namespace, AuthData) of
        Metadata when Metadata =/= undefined ->
            maps:get(Field, Metadata, undefined);
        undefined ->
            undefined
    end.
