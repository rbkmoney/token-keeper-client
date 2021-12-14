-module(token_keeper_client_codec).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([encode_token_context/1]).
-export([decode_authdata/1]).

%% Internal types

-type encoded_token_context() :: #token_keeper_TokenSourceContext{}.
-type decoded_token_context() :: token_keeper_client:token_context().

-type encoded_authdata() :: #token_keeper_AuthData{}.
-type decoded_authdata() :: token_keeper_client:auth_data().

%% API functions

-spec encode_token_context(decoded_token_context()) -> encoded_token_context().
encode_token_context(TokenContext) ->
    #token_keeper_TokenSourceContext{
        request_origin = maps:get(request_origin, TokenContext, undefined)
    }.

-spec decode_authdata(encoded_authdata()) -> decoded_authdata().
decode_authdata(#token_keeper_AuthData{
    id = ID,
    token = Token,
    status = Status,
    context = Context,
    metadata = Metadata,
    authority = Authority
}) ->
    #{
        id => ID,
        token => Token,
        status => Status,
        context => Context,
        metadata => Metadata,
        authority => Authority
    }.
