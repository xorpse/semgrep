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
   Entry point for the 'semgrep serve' subcommand.

   This module:
   - Initializes Eio and the executor pool
   - Loads default rules if specified
   - Starts the scan server
*)

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

(* Capabilities required by the serve subcommand *)
type caps = < Cap.stdout ; Cap.time_limit >

(*****************************************************************************)
(* Main implementation *)
(*****************************************************************************)

let run_conf (caps : < caps ; .. >) (conf : Scan_server_CLI.conf) : Exit_code.t =
  CLI_common.with_logging ~color:Auto ~level:conf.common.logging_level
  @@ fun () ->
  Logs.debug (fun m -> m "Starting semgrep-serve");
  Logs.info (fun m ->
      m "Configuration: workers=%d, timeout=%.1f"
        conf.workers conf.timeout);

  (* Create server state *)
  let state = Server_state.create ~default_timeout:conf.timeout in

  (* Load default rules if specified *)
  (match conf.rules_file with
   | Some rules_path ->
       Logs.info (fun m -> m "Loading rules from %s" (Fpath.to_string rules_path));
       (match Scan_handler.load_rules_from_file rules_path with
        | Ok rules ->
            Server_state.add_default_session state rules;
            Logs.info (fun m -> m "Loaded %d rules into default session" (List.length rules))
        | Error msg ->
            Logs.err (fun m -> m "Failed to load rules: %s" msg);
            Error.abort (Printf.sprintf "Failed to load rules: %s" msg))
   | None ->
       Logs.info (fun m -> m "No default rules specified"));

  (* Run the server under Eio *)
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->

  (* Create the executor pool for parallel scanning *)
  let pool =
    Executor_pool.create
      ~sw
      ~domain_count:conf.workers
      (Eio.Stdenv.domain_mgr env)
  in
  Logs.info (fun m -> m "Created executor pool with %d workers" conf.workers);

  (* Create server config *)
  let server_config : Scan_server.server_config = {
    state;
    caps = (caps :> Scan_server.server_caps);
    pool;
  } in

  (* Start the server *)
  let net = Eio.Stdenv.net env in
  Scan_server.run_server
    ~sw
    ~net
    ~transport:conf.transport
    ~config:server_config;

  (* Server has shut down *)
  let requests, scans = Server_state.get_stats state in
  Logs.info (fun m ->
      m "Server shutdown complete. Total requests: %d, Total scans: %d"
        requests scans);

  Exit_code.ok ~__LOC__

(*****************************************************************************)
(* Entry point *)
(*****************************************************************************)

let main (caps : < caps ; .. >) (argv : string array) : Exit_code.t =
  let conf = Scan_server_CLI.parse_argv argv in
  run_conf caps conf
