(*
   Copyright (c) 2025 Semgrep Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
   LICENSE for more details.
*)
module Arg = Cmdliner.Arg
module Term = Cmdliner.Term
module Cmd = Cmdliner.Cmd

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(*
   'semgrep serve' command-line arguments processing.

   This subcommand runs a concurrent JSON-RPC server for in-memory code scanning.
   It supports both TCP and Unix socket transports.
*)

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

(* Transport configuration - either TCP or Unix socket *)
type transport =
  | TCP of { host : string; port : int }
  | Unix_socket of { path : Fpath.t }
[@@deriving show]

(* The result of parsing a 'semgrep serve' command *)
type conf = {
  transport : transport;
  workers : int;
  rules_file : Fpath.t option;
  timeout : float;
  common : CLI_common.conf;
}
[@@deriving show]

(*****************************************************************************)
(* Command-line flags *)
(*****************************************************************************)

(* Transport options *)

let o_port : int option Term.t =
  let info =
    Arg.info [ "port"; "p" ]
      ~docv:"PORT"
      ~doc:"TCP port to listen on (e.g., --port 9876). Mutually exclusive with --socket."
  in
  Arg.value (Arg.opt (Arg.some Arg.int) None info)

let o_socket : string option Term.t =
  let info =
    Arg.info [ "socket"; "s" ]
      ~docv:"PATH"
      ~doc:"Unix socket path to listen on (e.g., --socket /tmp/semgrep.sock). \
            Mutually exclusive with --port."
  in
  Arg.value (Arg.opt (Arg.some Arg.string) None info)

let o_host : string Term.t =
  let info =
    Arg.info [ "host" ]
      ~docv:"HOST"
      ~doc:"Host to bind TCP socket to (default: 127.0.0.1). Only used with --port."
  in
  Arg.value (Arg.opt Arg.string "127.0.0.1" info)

(* Worker configuration *)

let o_workers : int option Term.t =
  let info =
    Arg.info [ "workers"; "j" ]
      ~docv:"N"
      ~doc:"Number of worker domains for parallel scanning (default: number of CPU cores)."
  in
  Arg.value (Arg.opt (Arg.some Arg.int) None info)

(* Rules configuration *)

let o_rules : string option Term.t =
  let info =
    Arg.info [ "rules"; "config"; "c" ]
      ~docv:"FILE"
      ~doc:"Preload rules from FILE into the default session on startup. \
            These rules will be used when no session_id is specified in scan requests."
  in
  Arg.value (Arg.opt (Arg.some Arg.string) None info)

(* Timeout configuration *)

let o_timeout : float Term.t =
  let info =
    Arg.info [ "timeout" ]
      ~docv:"SECONDS"
      ~doc:"Default scan timeout in seconds (default: 30.0)."
  in
  Arg.value (Arg.opt Arg.float 30.0 info)

(*****************************************************************************)
(* Command-line parsing: turn argv into conf *)
(*****************************************************************************)

let cmdline_term : conf Term.t =
  (* Parameters must be in alphabetic order to match the order
     of the corresponding '$ o_xx $' further below! *)
  let combine common host port rules socket timeout workers =
    (* Determine transport based on provided options *)
    let transport =
      match (port, socket) with
      | None, None ->
          Error.abort "Must specify either --port or --socket"
      | Some _, Some _ ->
          Error.abort "--port and --socket are mutually exclusive"
      | Some p, None ->
          if p < 1 || p > 65535 then
            Error.abort (Printf.sprintf "Invalid port number: %d (must be 1-65535)" p);
          TCP { host; port = p }
      | None, Some s ->
          Unix_socket { path = Fpath.v s }
    in
    (* Determine number of workers *)
    let workers =
      match workers with
      | Some n ->
          if n < 1 then
            Error.abort (Printf.sprintf "Invalid worker count: %d (must be >= 1)" n);
          n
      | None ->
          (* Default to number of CPU cores, capped at recommended domain count *)
          let recommended = Domain.recommended_domain_count () in
          max 1 (recommended - 1)  (* Leave one for the main domain *)
    in
    (* Convert rules string to Fpath if specified *)
    let rules_file = Option.map Fpath.v rules in
    { transport; workers; rules_file; timeout; common }
  in
  Term.(const combine
        $ CLI_common.o_common
        $ o_host
        $ o_port
        $ o_rules
        $ o_socket
        $ o_timeout
        $ o_workers)

let doc = "Run a concurrent JSON-RPC server for in-memory code scanning (EXPERIMENTAL)"

let man : Cmdliner.Manpage.block list =
  [
    `S Cmdliner.Manpage.s_description;
    `P "Starts a JSON-RPC 2.0 server that accepts scan requests over TCP or Unix \
        sockets. The server supports concurrent scanning using OCaml 5 multicore \
        domains for high throughput.";
    `P "The server accepts the following JSON-RPC methods:";
    `I ("$(b,scan)", "Scan code from a string with specified rules");
    `I ("$(b,initialize)", "Preload rules for a named session");
    `I ("$(b,shutdown)", "Gracefully shut down the server");
    `S Cmdliner.Manpage.s_examples;
    `P "Start server on TCP port 9876:";
    `Pre "    semgrep serve --port 9876 --rules rules.yaml";
    `P "Start server on Unix socket:";
    `Pre "    semgrep serve --socket /tmp/semgrep.sock";
    `P "Start with custom worker count:";
    `Pre "    semgrep serve --port 9876 --workers 4";
  ]
  @ CLI_common.help_page_bottom

let cmdline_info : Cmd.info = Cmd.info "semgrep serve" ~doc ~man

(*****************************************************************************)
(* Entry point *)
(*****************************************************************************)

let parse_argv (argv : string array) : conf =
  let cmd : conf Cmd.t = Cmd.v cmdline_info cmdline_term in
  CLI_common.eval_value ~argv cmd
