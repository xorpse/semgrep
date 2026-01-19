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
  mutable last_accessed_at : float;
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

  (* Session management *)
  session_ttl : float option;  (* None = no expiration, Some seconds = idle timeout *)
  max_sessions : int option;   (* None = unlimited, Some n = max concurrent sessions *)

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

let create ~default_timeout ?session_ttl ?max_sessions () : t = {
  sessions = Hashtbl.create 16;
  sessions_mutex = Mutex.create ();
  shutdown_requested = false;
  shutdown_mutex = Mutex.create ();
  default_timeout;
  session_ttl;
  max_sessions;
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
      let now = Unix.gettimeofday () in
      let session = { rules; created_at = now; last_accessed_at = now } in
      Hashtbl.replace state.sessions session_id session)

let get_session ?(touch = false) (state : t) (session_id : string) : session option =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      match Hashtbl.find_opt state.sessions session_id with
      | Some session ->
          if touch then session.last_accessed_at <- Unix.gettimeofday ();
          Some session
      | None -> None)

let get_session_rules (state : t) (session_id : string) : Rule.t list option =
  (* Touch the session on access to update last_accessed_at *)
  match get_session ~touch:true state session_id with
  | Some session -> Some session.rules
  | None -> None

let touch_session (state : t) (session_id : string) : bool =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      match Hashtbl.find_opt state.sessions session_id with
      | Some session ->
          session.last_accessed_at <- Unix.gettimeofday ();
          true
      | None -> false)

let remove_session (state : t) (session_id : string) : unit =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.remove state.sessions session_id)

let has_session (state : t) (session_id : string) : bool =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.mem state.sessions session_id)

type session_info = {
  id : string;
  created_at : float;
  last_accessed_at : float;
  rules_count : int;
}

let list_sessions (state : t) : session_info list =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.fold (fun session_id (sess : session) acc ->
          { id = session_id;
            created_at = sess.created_at;
            last_accessed_at = sess.last_accessed_at;
            rules_count = List.length sess.rules;
          } :: acc
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

(*****************************************************************************)
(* Session cleanup *)
(*****************************************************************************)

let session_count (state : t) : int =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      Hashtbl.length state.sessions)

(* Evict sessions that have been idle longer than the TTL.
   The _default session is never evicted. *)
let evict_stale_sessions (state : t) : int =
  match state.session_ttl with
  | None -> 0
  | Some ttl ->
      Mutex.lock state.sessions_mutex;
      Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
          let now = Unix.gettimeofday () in
          let to_remove =
            Hashtbl.fold (fun id (sess : session) acc ->
                if id <> default_session_id &&
                   now -. sess.last_accessed_at > ttl then
                  id :: acc
                else
                  acc
              ) state.sessions []
          in
          List.iter (Hashtbl.remove state.sessions) to_remove;
          List.length to_remove)

(* Evict the least recently used session (excluding _default) to make room.
   Returns true if a session was evicted. *)
let evict_lru_session (state : t) : bool =
  Mutex.lock state.sessions_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock state.sessions_mutex) (fun () ->
      let lru =
        Hashtbl.fold (fun id (sess : session) acc ->
            if id = default_session_id then acc
            else match acc with
              | None -> Some (id, sess.last_accessed_at)
              | Some (_, oldest_time) ->
                  if sess.last_accessed_at < oldest_time then
                    Some (id, sess.last_accessed_at)
                  else acc
          ) state.sessions None
      in
      match lru with
      | Some (id, _) ->
          Hashtbl.remove state.sessions id;
          true
      | None -> false)

(* Check if adding a new session would exceed max_sessions limit.
   If so, evict LRU sessions until there's room.
   Returns true if there's room for a new session. *)
let ensure_session_capacity (state : t) : bool =
  match state.max_sessions with
  | None -> true
  | Some max ->
      let rec make_room () =
        if session_count state < max then true
        else if evict_lru_session state then make_room ()
        else false
      in
      make_room ()
