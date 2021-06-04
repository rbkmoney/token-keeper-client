-module(tk_client_woody).

-export([call/3]).
-export([call/4]).

-define(APP, token_keeper_client).
-define(DEFAULT_DEADLINE, 5000).

%%

-type client_config() :: #{
    url := woody:url(),
    timeout => non_neg_integer(),
    retries => #{woody:func() | '_' => genlib_retry:strategy()}
}.

-type context() :: woody_context:ctx().

-spec call(woody:func(), woody:args(), context()) -> woody:result().
call(Function, Args, Context) ->
    EventHandler = scoper_woody_event_handler,
    call(Function, Args, Context, EventHandler).

-spec call(woody:func(), woody:args(), context(), woody:ev_handler()) -> woody:result().
call(Function, Args, Context0, EventHandler) ->
    Config = get_service_client_config(),
    Deadline = get_service_deadline(Config),
    Context1 = ensure_deadline_set(Deadline, Context0),
    Retry = get_service_retry(Function, Config),
    Request = {{tk_token_keeper_thrift, 'TokenKeeper'}, Function, Args},
    Opts = #{
        url => get_service_client_url(Config),
        event_handler => EventHandler
    },
    call_retry(Request, Context1, Opts, Retry).

-spec call_retry(woody:request(), woody_context:ctx(), woody_client:options(), genlib_retry:strategy()) ->
    woody:result().
call_retry(Request, Context, Opts, Retry) ->
    try
        woody_client:call(Request, Opts, Context)
    catch
        error:{woody_error, {_Source, Class, _Details}} = Error when
            Class =:= resource_unavailable orelse Class =:= result_unknown
        ->
            NextRetry = apply_retry_strategy(Retry, Error, Context),
            call_retry(Request, Context, Opts, NextRetry)
    end.

-type next_step() :: {wait, Timeout :: pos_integer(), genlib_retry:strategy()} | finish.
-type woody_system_error() :: {woody_error, woody_error:system_error()}.

-spec apply_retry_strategy(genlib_retry:strategy(), woody_system_error(), woody_context:ctx()) ->
    genlib_retry:strategy().
apply_retry_strategy(Retry, Error, Context) ->
    apply_retry_step(genlib_retry:next_step(Retry), get_deadline_ms(Context), Error).

-spec get_deadline_ms(woody_context:ctx()) -> undefined | non_neg_integer().
get_deadline_ms(Context) ->
    case woody_context:get_deadline(Context) of
        undefined ->
            undefined;
        Deadline ->
            woody_deadline:to_unixtime_ms(Deadline)
    end.

-spec apply_retry_step(next_step(), undefined | non_neg_integer(), woody_system_error()) -> genlib_retry:strategy().
apply_retry_step(finish, _, Error) ->
    erlang:error(Error);
apply_retry_step({wait, Timeout, Retry}, undefined, _) ->
    ok = timer:sleep(Timeout),
    Retry;
apply_retry_step({wait, Timeout, Retry}, DeadlineMs, Error) when DeadlineMs > Timeout ->
    Deadline1 = woody_deadline:from_unixtime_ms(DeadlineMs - Timeout),
    case woody_deadline:is_reached(Deadline1) of
        true ->
            % no more time for retries
            erlang:error(Error);
        false ->
            ok = timer:sleep(Timeout),
            Retry
    end.

-spec get_service_client_config() -> client_config().
get_service_client_config() ->
    genlib_app:env(?APP, service_client, #{}).

-spec get_service_client_url(client_config()) -> woody:url().
get_service_client_url(ClientConfig) ->
    maps:get(url, ClientConfig).

-spec get_service_deadline(client_config()) -> undefined | woody_deadline:deadline().
get_service_deadline(ClientConfig) ->
    case maps:get(timeout, ClientConfig, undefined) of
        undefined -> undefined;
        Timeout -> woody_deadline:from_timeout(Timeout)
    end.

-spec get_service_retry(woody:func(), client_config()) -> genlib_retry:strategy().
get_service_retry(Function, ClientConfig) ->
    FunctionRetries = maps:get(retries, ClientConfig, #{}),
    DefaultRetry = maps:get('_', FunctionRetries, finish),
    maps:get(Function, FunctionRetries, DefaultRetry).

-spec ensure_deadline_set(woody_deadline:deadline(), woody_context:ctx()) -> woody_context:ctx().
ensure_deadline_set(undefined, Context) ->
    case woody_context:get_deadline(Context) of
        undefined ->
            set_default_deadline(Context);
        _AlreadySet ->
            Context
    end;
ensure_deadline_set(Deadline, Context) ->
    set_deadline(Deadline, Context).

-spec set_default_deadline(woody_context:ctx()) -> woody_context:ctx().
set_default_deadline(Context) ->
    set_deadline(woody_deadline:from_timeout(?DEFAULT_DEADLINE), Context).

-spec set_deadline(woody_deadline:deadline(), woody_context:ctx()) -> woody_context:ctx().
set_deadline(Deadline, Context) ->
    woody_context:set_deadline(Deadline, Context).
