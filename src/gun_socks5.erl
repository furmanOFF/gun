-module(gun_socks5).

%% API
-export([connect/4, check_options/1]).

-type opt() :: 
    {host, inet:ip_address() | inet:hostname()} |
    {port, inet:port_number()} |
    {user, binary()} |
    {pass, binary()} |
    {resolve, remote | local}.
-type opts() :: [opt()].
-export_type([opts/0, opt/0]).

%% API
connect(Host, Port, Opts=#{host:=ProxyHost, port:=ProxyPort}, Timeout) ->
    TransportOpts = [binary, {active, false}, {packet, raw}, {keepalive, true}, {nodelay, true}],
    case gen_tcp:connect(ProxyHost, ProxyPort, TransportOpts, Timeout) of
        {ok, Socket} ->
            case do_handshake(Socket, Host, Port, Opts) of
                ok ->
                    {ok, Socket};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

check_options(#{host:=_, port:=_}=Opts) ->
    do_check_options(maps:to_list(Opts));
check_options(_) ->
    {error, {options, {socks5, badarg}}}.
%%
do_check_options([]) -> ok;
do_check_options([{host, _} | Opts]) ->
    do_check_options(Opts);
do_check_options([{port, Port} | Opts]) when is_integer(Port) ->
    do_check_options(Opts);
do_check_options([{user, User} | Opts]) when is_binary(User) ->
    do_check_options(Opts);
do_check_options([{pass, Pass} | Opts]) when is_binary(Pass) ->
    do_check_options(Opts);
do_check_options([{resolve, Resolve} | Opts]) when Resolve =:= remote; Resolve =:= local ->
    do_check_options(Opts);
do_check_options([Opt|_]) ->
    {error, {options, {socks5, Opt}}}.

do_handshake(Socket, Host, Port, Options) ->
    case Options of
        #{user := User} ->
            Pass = maps:get(pass, Options, <<>>),
            case do_authentication(Socket, User, Pass) of
                ok ->
                    do_connection(Socket, Host, Port, Options);
                Error ->
                    Error
            end;
        _ -> %% no auth
            ok = gen_tcp:send(Socket, << 5, 1, 0 >>),
            case gen_tcp:recv(Socket, 2, infinity) of
                {ok, << 5, 0 >>} ->
                    do_connection(Socket, Host, Port, Options);
                {ok, _Reply} ->
                    {error, unknown_reply};
                Error ->
                    Error
            end
    end.

do_authentication(Socket, User, Pass) ->
    ok = gen_tcp:send(Socket, << 5, 1, 2 >>),
    case gen_tcp:recv(Socket, 2, infinity) of
        {ok, <<5, 0>>} -> 
            ok;
        {ok, <<5, 2>>} ->
            UserLength = byte_size(User),
            PassLength = byte_size(Pass),
            Msg = << 1, UserLength, User/binary, PassLength, Pass/binary >>,
            ok = gen_tcp:send(Socket, Msg),
            case gen_tcp:recv(Socket, 2, infinity) of
                {ok, <<1, 0>>} -> 
                    ok;
                _ ->
                    {error, not_authenticated}
            end;
        _ ->
            {error, not_authenticated}
    end.

do_connection(Socket, Host, Port, Options) ->
    Resolve = maps:get(resolve, Options, remote),
    case addr(Host, Port, Resolve) of
        Addr when is_binary(Addr) ->
            ok = gen_tcp:send(Socket, << 5, 1, 0, Addr/binary >>),
            case gen_tcp:recv(Socket, 4, infinity) of
            {ok, << 5, 0, 0, AType>>} ->
                BoundAddr = recv_addr_port(AType, Socket),
                check_connection(BoundAddr);
            {ok, _} ->
                {error, badarg};
            Error ->
                Error
            end;
        Error ->
            Error
    end.

addr(Host, Port, Resolve) ->
  case inet_parse:address(Host) of
    {ok, {IP1, IP2, IP3, IP4}} ->
        << 1, IP1, IP2, IP3, IP4, Port:16 >>;
    {ok, {IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}} ->
        << 4, IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8, Port:16 >>;
    _ -> %% domain name
        case Resolve of
            local ->
                case inet:getaddr(Host, inet) of
                    {ok, {IP1, IP2, IP3, IP4}} ->
                    << 1, IP1, IP2, IP3, IP4, Port:16 >>;
                Error ->
                    case inet:getaddr(Host, inet6) of
                        {ok, {IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}} ->
                            << 4, IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8, Port:16 >>;
                        _ ->
                            Error
                    end
                end;
            _Remote ->
                Host1 = list_to_binary(Host),
                HostLength = byte_size(Host1),
                << 3, HostLength, Host1/binary, Port:16 >>
        end
  end.

recv_addr_port(1 = AType, Socket) -> % IPv4
    {ok, Data} = gen_tcp:recv(Socket, 6, infinity),
    <<AType, Data/binary>>;
recv_addr_port(4 = AType, Socket) -> % IPv6
    {ok, Data} = gen_tcp:recv(Socket, 18, infinity),
    <<AType, Data/binary>>;
recv_addr_port(3 = AType, Socket) -> % Domain
    {ok, <<DLen/integer>>} = gen_tcp:recv(Socket, 1, infinity),
    {ok, AddrPort} = gen_tcp:recv(Socket, DLen + 2, infinity),
    <<AType, DLen, AddrPort/binary>>;
recv_addr_port(_, _) ->
    error.

check_connection(<< 3, _DomainLen:8, _Domain/binary >>) ->
    ok;
check_connection(<< 1, _Addr:32, _Port:16 >>) ->
    ok;
check_connection(<< 4, _Addr:128, _Port:16 >>) ->
    ok;
check_connection(_) ->
    {error, no_connection}.