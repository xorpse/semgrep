(* Yoann Padioleau, Cooper Pierce
 *
 * Copyright (c) 2024, Semgrep Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation, with the
 * special exception on linking described in file LICENSE.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the file
 * LICENSE for more details.
 *)

(* See the mli for usage documentation *)

type t = {
  path : Target.path;
  analyzer : Analyzer.t;
  lazy_content : string Lazy_safe.t;
  lazy_ast_and_errors : (AST_generic.program * Tok.location list) Lazy_safe.t;
}

let parse_file parser (analyzer : Analyzer.t) path =
  let lang =
    (* Possibly better to determine this sooner/change how lazy_ast_and_errors
       works for regex or other non-parsing analyzers *)
    match analyzer with
    | L (lang, []) -> lang
    | L (_lang, _ :: _) ->
        failwith
          "analyzer from the language field in -target should be unique (this \
           shouldn't happen FIXME)"
    | _ ->
        (* alt: could return an empty program, but better to be defensive *)
        failwith "requesting generic AST for an unspecified target language"
  in
  parser lang path

let resolve_with_ast ast (target : Target.t) : t =
  {
    path = target.path;
    analyzer = target.analyzer;
    lazy_content =
      (match target.path.content with
      | Some content -> lazy_safe content
      | None -> lazy_safe (UFile.read_file target.path.internal_path_to_content));
    lazy_ast_and_errors = ast;
  }

let parse_content_from_string string_parser (analyzer : Analyzer.t) file content =
  let lang =
    match analyzer with
    | L (lang, []) -> lang
    | L (_lang, _ :: _) ->
        failwith
          "analyzer from the language field in -target should be unique (this \
           shouldn't happen FIXME)"
    | _ ->
        failwith "requesting generic AST for an unspecified target language"
  in
  string_parser lang file content

let resolve_with_string_parser file_parser string_parser (target : Target.t) : t =
  match target.path.content with
  | Some content ->
      (* In-memory target: use string parser *)
      let ast =
        lazy_safe
          (parse_content_from_string string_parser target.analyzer
             target.path.internal_path_to_content content)
      in
      resolve_with_ast ast target
  | None ->
      (* File-based target: use file parser *)
      let ast =
        lazy_safe
          (parse_file file_parser target.analyzer target.path.internal_path_to_content)
      in
      resolve_with_ast ast target

let resolve parser (target : Target.t) : t =
  match target.path.content with
  | Some _content ->
      (* For in-memory targets without a string parser, we still need to handle them.
         Fall back to writing content to the internal_path if needed, but that shouldn't
         happen if callers use resolve_with_string_parser for in-memory targets. *)
      failwith "resolve: in-memory targets require resolve_with_string_parser"
  | None ->
      let ast =
        lazy_safe
          (parse_file parser target.analyzer target.path.internal_path_to_content)
      in
      resolve_with_ast ast target
