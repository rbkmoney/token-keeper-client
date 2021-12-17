-module(token_keeper_mock).

-behaviour(woody_server_thrift_handler).

-export([handle_function/4]).

-type handler_fun() :: fun((Function :: atom(), Args :: tuple()) -> handler_fun_result()).
-type handler_fun_result() :: {ok, Result :: term()}.

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), #{function := handler_fun()}) ->
    handler_fun_result().
handle_function(FunName, Args, _, #{function := Fun}) ->
    Fun(FunName, Args).
