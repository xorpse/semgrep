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
(** 'semgrep serve' command-line arguments processing. *)

(** Transport configuration - either TCP or Unix socket *)
type transport =
  | TCP of { host : string; port : int }
  | Unix_socket of { path : Fpath.t }
[@@deriving show]

(** The result of parsing a 'semgrep serve' command *)
type conf = {
  transport : transport;
  workers : int;
  rules_file : Fpath.t option;
  timeout : float;
  common : CLI_common.conf;
}
[@@deriving show]

(** Parse command-line arguments into a configuration. *)
val parse_argv : string array -> conf
