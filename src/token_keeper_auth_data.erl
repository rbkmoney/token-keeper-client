-module(token_keeper_auth_data).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([get_id/1]).
-export([get_token/1]).
-export([get_status/1]).
-export([get_context_fragment/1]).
-export([get_authority/1]).

-export([get_metadata/1]).
-export([get_metadata/2]).
-export([get_metadata/3]).

%% API types

-type auth_data() :: tk_token_keeper_thrift:'AuthData'().

-type id() :: tk_token_keeper_thrift:'AuthDataID'().
-type token() :: tk_token_keeper_thrift:'Token'().
-type status() :: tk_token_keeper_thrift:'AuthDataStatus'().
-type context_fragment() :: tk_token_keeper_thrift:'ContextFragment'().
-type metadata() :: #{metadata_ns() => metadata_content()}.
-type metadata_ns() :: tk_token_keeper_thrift:'MetadataNamespace'().
-type metadata_content() :: #{binary() => binary()}.
-type authority() :: tk_token_keeper_thrift:'Authority'().

-export_type([auth_data/0]).
-export_type([id/0]).
-export_type([token/0]).
-export_type([status/0]).
-export_type([context_fragment/0]).
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

-spec get_context_fragment(auth_data()) -> context_fragment().
get_context_fragment(#token_keeper_AuthData{context = Context}) ->
    Context.

-spec get_authority(auth_data()) -> authority().
get_authority(#token_keeper_AuthData{authority = Authority}) ->
    Authority.

%%

-spec get_metadata(auth_data()) -> metadata().
get_metadata(#token_keeper_AuthData{metadata = Metadata}) ->
    Metadata.

-spec get_metadata(metadata_ns(), auth_data()) -> metadata_content() | undefined.
get_metadata(MetadataNS, #token_keeper_AuthData{metadata = Metadata}) ->
    maps:get(MetadataNS, Metadata, undefined).

-spec get_metadata(metadata_ns(), binary(), auth_data()) -> binary() | undefined.
get_metadata(MetadataNS, FieldName, #token_keeper_AuthData{metadata = Metadata}) ->
    case maps:get(MetadataNS, Metadata, undefined) of
        #{FieldName := Value} -> Value;
        _ -> undefined
    end.
