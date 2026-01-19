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
   Thread-safe state management for the scan server.

   This module manages:
   - Session-based rule caching for efficient repeated scans
   - Shutdown signaling
   - Server statistics (optional)

   Thread safety is achieved using a Mutex for the session cache.
*)

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

(* A session contains preloaded rules *)
type session = {
  rules : Rule.t list;
  created_at : float;
}

(* Server state *)
type t = {
  (* Session cache: session_id -> session *)
  mutable sessions : (string, session) Hashtbl.t;
  sessions_mutex : Mutex.t;

  (* Shutdown flag *)
  mutable shutdown_requested : bool;
  shutdown_mutex : Mutex.t;

  (* Default timeout for scans *)
  default_timeout : float;

  (* Statistics *)
  mutable total_requests : int;
  mutable total_scans : int;
  stats_mutex : Mutex.t;
}

(*****************************************************************************)
(* Constants *)
(*****************************************************************************)

(* Default session ID used when rules are preloaded at startup *)
let default_session_id = "_default"

(*****************************************************************************)
(* Creation *)
(*****************************************************************************)

let create ~default_timeout : t = {
  sessions = Hashtbl.create 16;
  sessions_mutex = Mutex.create ();
  shutdown_requested = false;
  shutdown_mutex = Mutex.create ();
  default_timeout;
  total_requests = 0;
  total_scans = 0;
  stats_mutex = Mutex.create ();
}

(*****************************************************************************)
(* Session management *)
(*****************************************************************************)

let add_session (state : t) (session_id : string) (rules : Rule.t list) : unit =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      let session = { rules; created_at = Unix.gettimeofday () } in
      Hashtbl.replace state.sessions session_id session)

let get_session (state : t) (session_id : string) : session option =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.find_opt state.sessions session_id)

let get_session_rules (state : t) (session_id : string) : Rule.t list option =
  match get_session state session_id with
  | Some session -> Some session.rules
  | None -> None

let remove_session (state : t) (session_id : string) : unit =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.remove state.sessions session_id)

let has_session (state : t) (session_id : string) : bool =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.mem state.sessions session_id)

let list_sessions (state : t) : (string * float) list =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.fold (fun id session acc ->
          (id, session.created_at) :: acc
        ) state.sessions [])

(*****************************************************************************)
(* Default session helpers *)
(*****************************************************************************)

let add_default_session (state : t) (rules : Rule.t list) : unit =
  add_session state default_session_id rules

let get_default_rules (state : t) : Rule.t list option =
  get_session_rules state default_session_id

let has_default_session (state : t) : bool =
  has_session state default_session_id

(*****************************************************************************)
(* Shutdown management *)
(*****************************************************************************)

let request_shutdown (state : t) : unit =
  Mutex.lock state.shutdown_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.shutdown_mutex) (fun () ->
      state.shutdown_requested <- true)

let is_shutdown_requested (state : t) : bool =
  Mutex.lock state.shutdown_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.shutdown_mutex) (fun () ->
      state.shutdown_requested)

(*****************************************************************************)
(* Statistics *)
(*****************************************************************************)

let record_request (state : t) : unit =
  Mutex.lock state.stats_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.stats_mutex) (fun () ->
      state.total_requests <- state.total_requests + 1)

let record_scan (state : t) : unit =
  Mutex.lock state.stats_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.stats_mutex) (fun () ->
      state.total_scans <- state.total_scans + 1)

let get_stats (state : t) : int * int =
  Mutex.lock state.stats_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.stats_mutex) (fun () ->
      (state.total_requests, state.total_scans))
