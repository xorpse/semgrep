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

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(*
   Socket server implementation for the scan server.

   This module handles:
   - Creating TCP or Unix sockets using Eio
   - Accepting connections
   - Reading/writing JSON-RPC messages
   - Dispatching requests to handlers
   - Managing the executor pool for parallel scanning
*)

module P = Server_protocol

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

type server_caps = < Cap.time_limit >

type server_config = {
  state : Server_state.t;
  caps : server_caps;
  pool : Executor_pool.t;
}

(*****************************************************************************)
(* Connection handling *)
(*****************************************************************************)

(* Read a line from a buffered reader *)
let read_line (reader : Eio.Buf_read.t) : string option =
  try
    Some (Eio.Buf_read.line reader)
  with
  | End_of_file -> None

(* Write a line to a flow *)
let write_line (writer : _ Eio.Flow.sink) (line : string) : unit =
  Eio.Flow.copy_string (line ^ "\n") writer

(* Handle the 'scan' method *)
let handle_scan
    (config : server_config)
    (id : P.request_id)
    (params : Yojson.Safe.t option)
    : P.response =
  match P.parse_scan_params params with
  | Error err -> P.make_error_response id err
  | Ok scan_params ->
      (* Record the scan *)
      Server_state.record_scan config.state;

      (* Parse the language *)
      match Scan_handler.parse_language scan_params.language with
      | Error msg -> P.make_scan_error id msg
      | Ok lang ->
          (* Get the rules to use *)
          let rules_result =
            match scan_params.rules, scan_params.session_id with
            | Some rules_json, _ ->
                (* Inline rules take precedence *)
                Scan_handler.parse_rules_from_json rules_json
            | None, Some session_id ->
                (* Use session rules *)
                (match Server_state.get_session_rules config.state session_id with
                 | Some rules -> Ok rules
                 | None ->
                     Error (Printf.sprintf "Session not found: %s" session_id))
            | None, None ->
                (* Use default session rules *)
                (match Server_state.get_default_rules config.state with
                 | Some rules -> Ok rules
                 | None ->
                     Error "No rules specified and no default session configured")
          in
          match rules_result with
          | Error msg -> P.make_scan_error id msg
          | Ok rules ->
              (* Run the scan in the executor pool *)
              let timeout = config.state.default_timeout in
              let result =
                Executor_pool.submit config.pool ~weight:1.0 (fun () ->
                    Scan_handler.scan_content
                      config.caps
                      ~timeout
                      ~rules
                      ~content:scan_params.content
                      ~filename:scan_params.filename
                      ~lang)
              in
              match result with
              | Ok scan_result ->
                  P.make_success_response id (P.scan_result_to_json scan_result)
              | Error exn ->
                  P.make_internal_error id (Printexc.to_string exn)

(* Handle the 'initialize' method *)
let handle_initialize
    (config : server_config)
    (id : P.request_id)
    (params : Yojson.Safe.t option)
    : P.response =
  match P.parse_initialize_params params with
  | Error err -> P.make_error_response id err
  | Ok init_params ->
      let rules_result =
        match init_params.rules_file, init_params.rules_json with
        | Some file_path, _ ->
            Scan_handler.load_rules_from_file (Fpath.v file_path)
        | None, Some json ->
            Scan_handler.parse_rules_from_json json
        | None, None ->
            Error "Must specify either 'rules_file' or 'rules'"
      in
      match rules_result with
      | Error msg -> P.make_scan_error id msg
      | Ok rules ->
          Server_state.add_session config.state init_params.session_id rules;
          Logs.info (fun m ->
              m "Initialized session '%s' with %d rules"
                init_params.session_id (List.length rules));
          P.make_success_response id (`Assoc [
              ("session_id", `String init_params.session_id);
              ("rules_count", `Int (List.length rules));
            ])

(* Handle the 'shutdown' method *)
let handle_shutdown
    (config : server_config)
    (id : P.request_id)
    : P.response =
  Logs.info (fun m -> m "Shutdown requested");
  Server_state.request_shutdown config.state;
  let requests, scans = Server_state.get_stats config.state in
  P.make_success_response id (`Assoc [
      ("message", `String "Server shutting down");
      ("total_requests", `Int requests);
      ("total_scans", `Int scans);
    ])

(* Handle the 'status' method *)
let handle_status
    (config : server_config)
    (id : P.request_id)
    : P.response =
  let requests, scans = Server_state.get_stats config.state in
  let sessions = Server_state.list_sessions config.state in
  P.make_success_response id (`Assoc [
      ("status", `String "running");
      ("total_requests", `Int requests);
      ("total_scans", `Int scans);
      ("sessions", `List (List.map (fun (id, created_at) ->
           `Assoc [
             ("id", `String id);
             ("created_at", `Float created_at);
           ]) sessions));
    ])

(* Dispatch a request to the appropriate handler *)
let handle_request
    (config : server_config)
    (request : P.request)
    : P.response =
  Server_state.record_request config.state;
  match request.method_ with
  | "scan" -> handle_scan config request.id request.params
  | "initialize" -> handle_initialize config request.id request.params
  | "shutdown" -> handle_shutdown config request.id
  | "status" -> handle_status config request.id
  | _ -> P.make_method_not_found request.id request.method_

(* Process a single request line *)
let process_request (config : server_config) (line : string) : string =
  match P.parse_request line with
  | Error err ->
      P.format_response (P.make_error_response P.Null_id err)
  | Ok request ->
      let response = handle_request config request in
      P.format_response response

(* Handle a single client connection *)
let handle_connection (config : server_config) (flow : _ Eio.Net.stream_socket) : unit =
  let reader = Eio.Buf_read.of_flow ~max_size:(16 * 1024 * 1024) flow in
  try
    while not (Server_state.is_shutdown_requested config.state) do
      match read_line reader with
      | None ->
          (* Connection closed *)
          raise Exit
      | Some line when String.length (String.trim line) = 0 ->
          (* Empty line, skip *)
          ()
      | Some line ->
          let response = process_request config line in
          write_line flow response
    done
  with
  | Exit -> ()
  | End_of_file -> ()
  | e ->
      Logs.err (fun m ->
          m "Error handling connection: %s" (Printexc.to_string e))

(*****************************************************************************)
(* Server entry point *)
(*****************************************************************************)

let run_server
    ~(sw : Eio.Switch.t)
    ~(net : _ Eio.Net.t)
    ~(transport : Scan_server_CLI.transport)
    ~(config : server_config)
    : unit =
  (* Create the listening socket *)
  let socket =
    match transport with
    | Scan_server_CLI.TCP { host; port } ->
        let addr = `Tcp (Eio.Net.Ipaddr.V4.loopback, port) in
        (* For non-loopback, we'd need to parse the host string *)
        let _ = host in  (* TODO: support non-loopback hosts *)
        Logs.info (fun m -> m "Starting TCP server on %s:%d" host port);
        Eio.Net.listen net ~sw ~backlog:128 ~reuse_addr:true addr

    | Scan_server_CLI.Unix_socket { path } ->
        let socket_path = Fpath.to_string path in
        (* Remove existing socket file if it exists *)
        (try Unix.unlink socket_path with Unix.Unix_error _ -> ());
        let addr = `Unix socket_path in
        Logs.info (fun m -> m "Starting Unix socket server on %s" socket_path);
        Eio.Net.listen net ~sw ~backlog:128 ~reuse_addr:true addr
  in

  (* Accept loop *)
  while not (Server_state.is_shutdown_requested config.state) do
    Eio.Net.accept_fork socket ~sw (fun flow _addr ->
        Logs.debug (fun m -> m "Accepted new connection");
        handle_connection config flow;
        Logs.debug (fun m -> m "Connection closed"))
      ~on_error:(fun exn ->
          Logs.err (fun m ->
              m "Error accepting connection: %s" (Printexc.to_string exn)))
  done;

  Logs.info (fun m -> m "Server stopped")
